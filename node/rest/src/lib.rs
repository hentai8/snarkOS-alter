// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkOS library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![forbid(unsafe_code)]

#[macro_use]
extern crate tracing;

mod helpers;
// Imports custom `Path` type, to be used instead of `axum`'s.
pub use helpers::*;

mod history_compat;
use history_compat::*;

mod routes;

mod version;

use snarkos_node_cdn::CdnBlockSync;
use snarkos_node_consensus::Consensus;
use snarkos_node_router::{
    Routing,
    messages::{Message, UnconfirmedTransaction},
};
use snarkos_node_sync::BlockSync;
use snarkvm::{
    console::{program::ProgramID, types::Field},
    ledger::narwhal::Data,
    prelude::{Ledger, Network, VM, cfg_into_iter, store::ConsensusStorage},
};

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    middleware,
    response::Response,
    routing::{get, post},
};
use axum_extra::response::ErasedJson;
#[cfg(feature = "locktick")]
use locktick::parking_lot::Mutex;
use lru::LruCache;
#[cfg(not(feature = "locktick"))]
use parking_lot::Mutex;
use std::{net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinHandle};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::Span;

/// The default port used for the REST API
pub const DEFAULT_REST_PORT: u16 = 3030;

/// The API version prefixes.
pub const API_VERSION_V1: &str = "v1";
pub const API_VERSION_V2: &str = "v2";

/// The capacity of the LRU holding recently requested blocks.
const BLOCK_CACHE_SIZE: usize = 128;

/// A REST API server for the ledger.
#[derive(Clone)]
pub struct Rest<N: Network, C: ConsensusStorage<N>, R: Routing<N>> {
    /// CDN sync (only if node is using the CDN to sync).
    cdn_sync: Option<Arc<CdnBlockSync>>,
    /// The consensus module.
    consensus: Option<Consensus<N>>,
    /// The ledger.
    ledger: Ledger<N, C>,
    /// The node (routing).
    routing: Arc<R>,
    /// The server handles.
    handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// A reference to BlockSync,
    block_sync: Arc<BlockSync<N>>,
    /// The number of ongoing deploy transaction verifications via REST.
    num_verifying_deploys: Arc<Semaphore>,
    /// The number of ongoing execute transaction verifications via REST.
    num_verifying_executions: Arc<Semaphore>,
    /// The number of ongoing solution verifications via REST.
    num_verifying_solutions: Arc<Semaphore>,
    /// A cache containing recently requested blocks.
    block_cache: Arc<Mutex<LruCache<N::BlockHash, ErasedJson>>>,
    /// The upstream for the routes of the removed `history` feature, if `--history-compat-mode` is set.
    history_compat: Option<Arc<HistoryCompat>>,
}

impl<N: Network, C: 'static + ConsensusStorage<N>, R: Routing<N>> Rest<N, C, R> {
    /// Initializes a new instance of the server.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        rest_ip: SocketAddr,
        rest_rps: u32,
        history_api_url: Option<String>,
        consensus: Option<Consensus<N>>,
        ledger: Ledger<N, C>,
        routing: Arc<R>,
        cdn_sync: Option<Arc<CdnBlockSync>>,
        block_sync: Arc<BlockSync<N>>,
    ) -> Result<Self> {
        // Initialize the history compatibility upstream, if requested.
        let history_compat = match history_api_url {
            Some(url) => Some(Arc::new(HistoryCompat::new(&url, N::SHORT_NAME)?)),
            None => None,
        };
        // Initialize the server.
        let mut server = Self {
            consensus,
            ledger,
            routing,
            cdn_sync,
            block_sync,
            handles: Default::default(),
            num_verifying_deploys: Arc::new(Semaphore::new(VM::<N, C>::MAX_PARALLEL_DEPLOY_VERIFICATIONS)),
            num_verifying_executions: Arc::new(Semaphore::new(VM::<N, C>::MAX_PARALLEL_EXECUTE_VERIFICATIONS)),
            num_verifying_solutions: Arc::new(Semaphore::new(N::MAX_SOLUTIONS)),
            block_cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(BLOCK_CACHE_SIZE).unwrap()))),
            history_compat,
        };
        // Spawn the server.
        server.spawn_server(rest_ip, rest_rps).await?;
        // Return the server.
        Ok(server)
    }
}

impl<N: Network, C: ConsensusStorage<N>, R: Routing<N>> Rest<N, C, R> {
    /// Returns the ledger.
    pub const fn ledger(&self) -> &Ledger<N, C> {
        &self.ledger
    }

    /// Returns the handles.
    pub const fn handles(&self) -> &Arc<Mutex<Vec<JoinHandle<()>>>> {
        &self.handles
    }

    /// Shuts down the REST instance.
    pub fn shut_down(&self) {
        self.handles.lock().iter().for_each(|handle| handle.abort());
    }
}

impl<N: Network, C: ConsensusStorage<N>, R: Routing<N>> Rest<N, C, R> {
    fn build_routes(&self, rest_rps: u32) -> axum::Router {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
            .allow_headers([CONTENT_TYPE]);

        // Prepare the rate limiting setup.
        let governor_config = Box::new(
            GovernorConfigBuilder::default()
                .per_nanosecond((1_000_000_000 / rest_rps) as u64)
                .burst_size(rest_rps)
                .error_handler(|error| {
                    // Properly return a 429 Too Many Requests error
                    let error_message = error.to_string();
                    let mut response = Response::new(error_message.clone().into());
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    if error_message.contains("Too Many Requests") {
                        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                    }
                    response
                })
                .finish()
                .expect("Couldn't set up rate limiting for the REST server!"),
        );

        // Build the JWT auth-protected endpoints. #[cfg] cannot appear inside a method chain, so we
        // build this router as a named binding and conditionally extend it before applying the layer.
        let auth_routes = axum::Router::new()
            .route("/node/address", get(Self::get_node_address))
            .route("/program/{id}/mapping/{name}", get(Self::get_mapping_values))
            .route("/db_backup", post(Self::db_backup));

        // Slipstream plugin management endpoints require auth.
        #[cfg(feature = "slipstream-plugins")]
        let auth_routes = auth_routes
            .route("/slipstream/plugins", get(Self::slipstream_list_plugins).post(Self::slipstream_load_plugin))
            .route(
                "/slipstream/plugins/{name}",
                // TODO: PUT (reload) is not yet implemented.
                axum::routing::delete(Self::slipstream_unload_plugin),
            );

        let routes = axum::Router::new()
            .merge(auth_routes.route_layer(middleware::from_fn(auth_middleware)))

            // All endpoints declared after here are not protected

             // Get ../consensus_version
            .route("/consensus_version", get(Self::get_consensus_version))

            // GET ../block/..
            .route("/block/height/latest", get(Self::get_block_height_latest))
            .route("/block/hash/latest", get(Self::get_block_hash_latest))
            .route("/block/latest", get(Self::get_block_latest))
            .route("/block/{height_or_hash}", get(Self::get_block))
            // The path param here is actually only the height, but the name must match the route
            // above, otherwise there'll be a conflict at runtime.
            .route("/block/{height_or_hash}/header", get(Self::get_block_header))
            .route("/block/{height_or_hash}/transactions", get(Self::get_block_transactions))

            // GET and POST ../transaction/..
            .route("/transaction/{id}", get(Self::get_transaction))
            .route("/transaction/confirmed/{id}", get(Self::get_confirmed_transaction))
            .route("/transaction/unconfirmed/{id}", get(Self::get_unconfirmed_transaction))
            .route("/transaction/rejected/{id}/reason", get(Self::get_transaction_rejection_reason))
            .route("/transaction/broadcast", post(Self::transaction_broadcast))

            // GET and POST ../solution/..
            .route("/solution/limits/{prover_address}", get(Self::get_solution_limits_for_prover))
            .route("/solution/{solution_id}", get(Self::get_solution_metadata))
            .route("/solution/broadcast", post(Self::solution_broadcast))

            // GET ../find/..
            .route("/find/blockHash/{tx_id}", get(Self::find_block_hash))
            .route("/find/blockHeight/{state_root}", get(Self::find_block_height_from_state_root))
            .route("/find/transactionID/deployment/{program_id}", get(Self::find_latest_transaction_id_from_program_id))
            .route("/find/transactionID/deployment/{program_id}/{edition}", get(Self::find_latest_transaction_id_from_program_id_and_edition))
            .route("/find/transactionID/deployment/{program_id}/{edition}/original", get(Self::find_original_deployment_transaction_id))
            .route("/find/transactionID/deployment/{program_id}/{edition}/{amendment}", get(Self::find_transaction_id_from_program_id_edition_and_amendment))
            .route("/find/transactionID/{transition_id}", get(Self::find_transaction_id_from_transition_id))
            .route("/find/transitionID/{input_or_output_id}", get(Self::find_transition_id))

            // GET ../connections/p2p/.. (with ../peers/.. aliases)
            .route("/peers/count", get(Self::get_peers_count))
            .route("/peers/all", get(Self::get_peers_all))
            .route("/peers/all/metrics", get(Self::get_peers_all_metrics))
            .route("/connections/p2p/count", get(Self::get_peers_count))
            .route("/connections/p2p/all", get(Self::get_peers_all))
            .route("/connections/p2p/all/metrics", get(Self::get_peers_all_metrics))

            // GET ../program/..
            .route("/program/{id}", get(Self::get_program))
            .route("/program/{id}/latest_edition", get(Self::get_latest_program_edition))
            .route("/program/{id}/{edition}", get(Self::get_program_for_edition))
            .route("/program/{id}/mappings", get(Self::get_mapping_names))
            .route("/program/{id}/mapping/{name}/{key}", get(Self::get_mapping_value))
            .route("/program/{id}/amendment_count", get(Self::get_program_amendment_count))
            .route("/program/{id}/{edition}/amendment_count", get(Self::get_program_amendment_count_for_edition))

            // GET ../sync/..
            // Note: keeping ../sync_status for compatibility
            .route("/sync_status", get(Self::get_sync_status))
            .route("/sync/status", get(Self::get_sync_status))
            .route("/sync/peers", get(Self::get_sync_peers))
            .route("/sync/requests", get(Self::get_sync_requests_summary))
            .route("/sync/requests/list", get(Self::get_sync_requests_list))

            // GET misc endpoints.
            .route("/version", get(Self::get_version))
            .route("/blocks", get(Self::get_blocks))
            .route("/height/{hash}", get(Self::get_height))
            .route("/memoryPool/transmissions", get(Self::get_memory_pool_transmissions))
            .route("/memoryPool/solutions", get(Self::get_memory_pool_solutions))
            .route("/memoryPool/transactions", get(Self::get_memory_pool_transactions))
            .route("/statePath/{commitment}", get(Self::get_state_path_for_commitment))
            .route("/statePaths", get(Self::get_state_paths_for_commitments))
            .route("/stateRoot/latest", get(Self::get_state_root_latest))
            .route("/stateRoot/{height}", get(Self::get_state_root))
            .route("/committee/latest", get(Self::get_committee_latest))
            .route("/committee/{height}", get(Self::get_committee))
            .route("/delegators/{validator}", get(Self::get_delegators_for_validator));

        // If the node is a validator, enable the BFT connections endpoints.
        let routes = match self.consensus {
            Some(_) => routes
                .route("/connections/bft/count", get(Self::get_bft_connections_count))
                .route("/connections/bft/all", get(Self::get_bft_connections_all)),
            None => routes,
        };

        // If the node is a validator and `telemetry` features is enabled, enable the additional endpoint.
        #[cfg(feature = "metrics")]
        let routes = match self.consensus {
            Some(_) => routes.route("/validators/participation", get(Self::get_validator_participation_scores)),
            None => routes,
        };

        // Register the view-at-latest-height endpoint (always available, no history required).
        let routes = routes.route("/program/{id}/view/{function}", post(Self::evaluate_view_latest));

        // In history compatibility mode, serve the routes of the removed `history` feature from the
        // upstream historical API (see `history_compat`).
        let routes = if self.history_compat.is_some() {
            routes
                .route("/program/{id}/mapping/{name}/{key}/history/{height}", get(Self::get_history_compat))
                .route("/program/{id}/mapping/{name}/history/{height}", get(Self::get_history_batch_compat))
                .route("/program/{id}/view/{function}/{height}", post(Self::evaluate_view_at_height_compat))
                .route("/staking/rewards/{address}/{height}", get(Self::get_staking_reward_compat))
        } else {
            routes
        };

        // If the `history-staking-rewards` feature is enabled, enable the additional endpoint (unless
        // compatibility mode already serves it).
        #[cfg(feature = "history-staking-rewards")]
        let routes = if self.history_compat.is_some() {
            routes
        } else {
            routes.route("/staking/rewards/{address}/{height}", get(Self::get_staking_reward))
        };

        let trace_layer = TraceLayer::new_for_http()
            .make_span_with(|request: &Request<_>| {
                let addr = request
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ConnectInfo(addr)| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                // Create a span that includes method, path, and our extracted IP
                tracing::info_span!(
                    "REST",
                    method = %request.method(),
                    uri = %request.uri().path(),
                    addr = %addr,
                )
            })
            .on_request(|_request: &Request<_>, _span: &Span| {
                info!("Received a request");
            })
            .on_response(|_response: &Response<_>, latency: Duration, _span: &Span| {
                info!("Finished request in {:?}", latency);
            });

        routes
            // Pass in `Rest` to make things convenient.
            .with_state(self.clone())
            // Cap the request body size at 1.5MiB.
            .layer(DefaultBodyLimit::max(2 * 768 * 1024))
            .layer(GovernorLayer {
                config: governor_config.into(),
            })
            // Enable CORS.
            .layer(cors)
            // Enable tower-http tracing.
            .layer(trace_layer)
    }

    async fn spawn_server(&mut self, rest_ip: SocketAddr, rest_rps: u32) -> Result<()> {
        // Log the REST rate limit per IP.
        debug!("REST rate limit per IP - {rest_rps} RPS");

        // Add the v1 API as default and under "/v1".
        let default_router = axum::Router::new().nest(
            &format!("/{}", N::SHORT_NAME),
            self.build_routes(rest_rps).layer(middleware::map_response(v1_error_middleware)),
        );
        let v1_router = axum::Router::new().nest(
            &format!("/{API_VERSION_V1}/{}", N::SHORT_NAME),
            self.build_routes(rest_rps).layer(middleware::map_response(v1_error_middleware)),
        );

        // Add the v2 API under "/v2".
        let v2_router =
            axum::Router::new().nest(&format!("/{API_VERSION_V2}/{}", N::SHORT_NAME), self.build_routes(rest_rps));

        // Combine all routes.
        let router = default_router.merge(v1_router).merge(v2_router);

        let rest_listener =
            TcpListener::bind(rest_ip).await.with_context(|| "Failed to bind TCP port for REST endpoints")?;

        let handle = tokio::spawn(async move {
            axum::serve(rest_listener, router.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("couldn't start rest server");
        });

        self.handles.lock().push(handle);
        Ok(())
    }
}

/// Converts errors to the old style for the v1 API.
/// The error code will always be 500 and the content a simple string.
async fn v1_error_middleware(response: Response) -> Response {
    // The status code used by all v1 errors
    const V1_STATUS_CODE: StatusCode = StatusCode::INTERNAL_SERVER_ERROR;

    if response.status().is_success() {
        return response;
    }

    // Returns a opaque error instead of panicking.
    let fallback = || {
        let mut response = Response::new(Body::from("Failed to convert error"));
        *response.status_mut() = V1_STATUS_CODE;
        response
    };

    let Ok(bytes) = axum::body::to_bytes(response.into_body(), usize::MAX).await else {
        return fallback();
    };

    // Deserialize REST error so we can convert it to a string
    let Ok(json_err) = serde_json::from_slice::<SerializedRestError>(&bytes) else {
        return fallback();
    };

    let mut message = json_err.message;
    for next in json_err.chain.into_iter() {
        message = format!("{message} — {next}");
    }

    let mut response = Response::new(Body::from(message));

    *response.status_mut() = V1_STATUS_CODE;

    response
}

/// Formats an ID into a truncated identifier (for logging purposes).
pub fn fmt_id(id: impl ToString) -> String {
    let id = id.to_string();
    let mut formatted_id = id.chars().take(16).collect::<String>();
    if id.chars().count() > 16 {
        formatted_id.push_str("..");
    }
    formatted_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use tower::ServiceExt; // for `oneshot`

    fn test_app() -> Router {
        let build_routes = || {
            Router::new()
                .route("/not_found", get(|| async { Err::<(), RestError>(RestError::not_found(anyhow!("missing"))) }))
                .route("/bad_request", get(|| async { Err::<(), RestError>(RestError::bad_request(anyhow!("bad"))) }))
                .route(
                    "/service_unavailable",
                    get(|| async { Err::<(), RestError>(RestError::service_unavailable(anyhow!("gone"))) }),
                )
        };
        let router_v1 = build_routes().route_layer(middleware::map_response(v1_error_middleware));
        let router_v2 = Router::new().nest(&format!("/{API_VERSION_V2}"), build_routes());
        router_v1.merge(router_v2)
    }

    #[tokio::test]
    async fn v1_routes_force_internal_server_error() {
        let app = test_app();

        let res = app.clone().oneshot(Request::builder().uri("/not_found").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let res =
            app.clone().oneshot(Request::builder().uri("/bad_request").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let res =
            app.oneshot(Request::builder().uri("/service_unavailable").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn v2_routes_return_specific_errors() {
        let app = test_app();

        let res =
            app.clone().oneshot(Request::builder().uri("/v2/not_found").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res =
            app.clone().oneshot(Request::builder().uri("/v2/bad_request").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let res =
            app.oneshot(Request::builder().uri("/v2/service_unavailable").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;
    use snarkos_node_bft_ledger_service::MockLedgerService;
    use snarkos_node_network::ConnectionMode;
    use snarkos_node_router::test_helpers::{TestRouter, client, sample_genesis_block};
    use snarkvm::{
        ledger::{committee::test_helpers::sample_committee, store::helpers::memory::ConsensusMemory},
        prelude::MainnetV0,
        utilities::TestRng,
    };

    use aleo_std::StorageMode;
    use axum::body::to_bytes;
    use tower::ServiceExt; // for `oneshot`

    type CurrentNetwork = MainnetV0;
    type CurrentRest = Rest<CurrentNetwork, ConsensusMemory<CurrentNetwork>, TestRouter<CurrentNetwork>>;

    /// The rate limit given to the router under test. The governor layer is applied by
    /// `build_routes`, so this is set high enough that a test making several requests in quick
    /// succession is never the thing that trips it.
    const TEST_RPS: u32 = 1_000;

    /// Builds a `Rest` over an in-memory ledger containing only the genesis block.
    ///
    /// This constructs the struct directly rather than calling `Rest::start`, which would bind a
    /// port and spawn a server. None of the routes exercised here touch `consensus`, `cdn_sync`,
    /// `routing` or `block_sync`; those fields exist only to satisfy the type.
    async fn sample_rest() -> CurrentRest {
        let rng = &mut TestRng::default();

        // `Ledger::load` reaches snarkVM's sequential-operation thread and blocks on the reply,
        // which panics if called from an async context. Production always drives these from a
        // blocking task, so do the same here.
        let ledger = tokio::task::spawn_blocking(|| {
            Ledger::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::load(
                sample_genesis_block::<CurrentNetwork>(),
                StorageMode::new_test(None),
            )
        })
        .await
        .expect("the ledger task panicked")
        .expect("couldn't load the test ledger");

        let ledger_service = Arc::new(MockLedgerService::new(sample_committee(rng)));

        Rest {
            cdn_sync: None,
            consensus: None,
            ledger,
            routing: Arc::new(client(0, 10, rng).await),
            handles: Default::default(),
            block_sync: Arc::new(BlockSync::new(ledger_service, ConnectionMode::Router)),
            num_verifying_deploys: Arc::new(Semaphore::new(1)),
            num_verifying_executions: Arc::new(Semaphore::new(1)),
            num_verifying_solutions: Arc::new(Semaphore::new(1)),
            block_cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(BLOCK_CACHE_SIZE).unwrap()))),
            history_compat: None,
        }
    }

    /// Issues a GET request against the routes, without the network prefix that `spawn_server`
    /// nests them under.
    async fn get(rest: &CurrentRest, uri: &str) -> (StatusCode, String) {
        request(rest, Method::GET, uri).await
    }

    /// Issues a request against the routes, without the network prefix that `spawn_server` nests
    /// them under.
    ///
    /// The governor layer keys on the peer IP taken from `ConnectInfo`, which a request built by
    /// hand does not carry, so this attaches one; without it every request fails the rate limiter's
    /// key extractor rather than reaching a handler.
    async fn request(rest: &CurrentRest, method: Method, uri: &str) -> (StatusCode, String) {
        let mut request = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4130))));

        let response = rest.build_routes(TEST_RPS).oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn latest_block_hash_is_the_genesis_hash() {
        let rest = sample_rest().await;

        // The test ledger holds only the genesis block.
        let (status, body) = get(&rest, "/block/hash/latest").await;
        assert_eq!(status, StatusCode::OK);

        let hash: <CurrentNetwork as Network>::BlockHash = serde_json::from_str(&body).unwrap();
        assert_eq!(hash, sample_genesis_block::<CurrentNetwork>().hash());
    }

    /// The routes of the removed `history` feature, in history compatibility mode.
    mod history_compat {
        use super::*;
        use crate::history_compat::fixtures;

        /// A stand-in for the upstream historical API: serves the block-1,000,000 fixtures at every
        /// height for the mappings it has, and for `withdraw` the 500 that the real upstream answers
        /// for a height it has no snapshot of.
        async fn spawn_upstream() -> String {
            async fn snapshot(Path((_height, mapping)): Path<(u32, String)>) -> (StatusCode, &'static str) {
                match mapping.as_str() {
                    "unbonding" => (StatusCode::OK, fixtures::UNBONDING),
                    "bonded" => (StatusCode::OK, fixtures::BONDED),
                    "stakingrewards" => (StatusCode::OK, fixtures::STAKING_REWARDS),
                    "metadata" => (StatusCode::OK, fixtures::METADATA),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, fixtures::MISSING),
                }
            }
            let app =
                axum::Router::new().route("/mainnet/block/{height}/history/{mapping}", axum::routing::get(snapshot));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            format!("http://{address}")
        }

        /// A `Rest` in history compatibility mode against the stub upstream.
        async fn sample_compat_rest() -> CurrentRest {
            let mut rest = sample_rest().await;
            rest.history_compat = Some(Arc::new(HistoryCompat::new(&spawn_upstream().await, "mainnet").unwrap()));
            rest
        }

        const UNBONDING_STAKER: &str = "aleo1sdjqhlcm9qltpu74ek0vxewt52zsdmn6swmpjn6m0tp9xf57dvpq740r8j";
        const BONDED_STAKER: &str = "aleo1qy4qufq03wcph05fdf5aj09ez67vcmmlrzqf0zza352qwaq43gyqt3wdf6";
        const VALIDATOR: &str = "aleo1vfukg8ky2mhfprw63s0k0hl4vvd8573s6fkn8cv9y0ca6q27eq8qwdnxls";

        #[tokio::test]
        async fn history_serves_the_value_from_the_upstream_snapshot() {
            let rest = sample_compat_rest().await;
            // The test ledger is at height 0, so that is the one height the upstream is asked for.
            let (status, body) =
                get(&rest, &format!("/program/credits.aleo/mapping/unbonding/{UNBONDING_STAKER}/history/0")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            // The body is the value's plaintext string, as the removed feature returned it.
            let value: Option<String> = serde_json::from_str(&body).unwrap();
            assert_eq!(value.as_deref(), Some("{\n  microcredits: 10113730488u64,\n  height: 621255u32\n}"));
        }

        #[tokio::test]
        async fn history_answers_null_for_an_absent_key() {
            let rest = sample_compat_rest().await;
            // A key absent from the snapshot: e.g. an unbond that was claimed.
            let (status, body) =
                get(&rest, &format!("/program/credits.aleo/mapping/unbonding/{BONDED_STAKER}/history/0")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body.trim(), "null");
        }

        #[tokio::test]
        async fn history_is_served_regardless_of_the_node_height() {
            // The test ledger is at height 0; the upstream is the source of truth, so a height far
            // above the node's is answered from it all the same.
            let rest = sample_compat_rest().await;
            let (status, body) =
                get(&rest, &format!("/program/credits.aleo/mapping/unbonding/{UNBONDING_STAKER}/history/1000000"))
                    .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let value: Option<String> = serde_json::from_str(&body).unwrap();
            assert!(value.is_some());
            let (status, body) = get(&rest, &format!("/staking/rewards/{BONDED_STAKER}/1000000")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_ne!(body.trim(), "null");
        }

        #[tokio::test]
        async fn history_batch_serves_every_key_from_one_snapshot() {
            let rest = sample_compat_rest().await;
            let (status, body) = get(
                &rest,
                &format!("/program/credits.aleo/mapping/unbonding/history/0?keys={UNBONDING_STAKER},{BONDED_STAKER}"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let values: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
            assert_eq!(values.len(), 2);
            assert_eq!(values[0]["key"], UNBONDING_STAKER);
            assert_eq!(values[0]["value"], "{\n  microcredits: 10113730488u64,\n  height: 621255u32\n}");
            assert_eq!(values[1]["key"], BONDED_STAKER);
            assert_eq!(values[1]["value"], serde_json::Value::Null);
        }

        #[tokio::test]
        async fn history_rejects_what_the_upstream_does_not_record() {
            let rest = sample_compat_rest().await;
            // A `credits.aleo` mapping the upstream has no snapshot of.
            let (status, body) =
                get(&rest, &format!("/program/credits.aleo/mapping/committee/{VALIDATOR}/history/0")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
            assert!(body.contains("credits.aleo/committee"), "{body}");
            // Another program.
            let (status, body) = get(&rest, "/program/other.aleo/mapping/bonded/1field/history/0").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
            assert!(body.contains("other.aleo/bonded"), "{body}");
            // A supported mapping for which the upstream has no snapshot at that height (which it
            // reports as a 500, not a 404).
            let (status, body) =
                get(&rest, &format!("/program/credits.aleo/mapping/withdraw/{VALIDATOR}/history/0")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
            assert!(body.contains("No snapshot of 'withdraw'"), "{body}");
            // A view at a past height.
            let (status, body) = request(&rest, Method::POST, "/program/credits.aleo/view/anything/0").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
            assert!(body.contains("latest height"), "{body}");
        }

        #[tokio::test]
        async fn staking_reward_joins_the_rewards_and_bonded_snapshots() {
            let rest = sample_compat_rest().await;
            let (status, body) = get(&rest, &format!("/staking/rewards/{BONDED_STAKER}/0")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            // `[validator, reward, new_stake]`, as the `history-staking-rewards` feature returned it.
            let reward: (String, u64, u64) = serde_json::from_str(&body).unwrap();
            assert_eq!(reward, (VALIDATOR.to_string(), 6477, 141_347_021_440));
            // A staker with no reward at that height.
            let (status, body) = get(&rest, &format!("/staking/rewards/{UNBONDING_STAKER}/0")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body.trim(), "null");
        }

        #[tokio::test]
        async fn history_routes_are_absent_without_compatibility_mode() {
            let rest = sample_rest().await;
            let (status, _) =
                get(&rest, &format!("/program/credits.aleo/mapping/unbonding/{UNBONDING_STAKER}/history/0")).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }
}
