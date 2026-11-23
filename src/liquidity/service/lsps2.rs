// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::cmp::Reverse;
use std::ops::Deref;
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Transaction;
use chrono::Utc;
use lightning::events::HTLCHandlingFailureType;
use lightning::ln::channelmanager::InterceptId;
use lightning::ln::types::ChannelId;
use lightning::sign::EntropySource;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;
use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig as LdkLSPS2ServiceConfig;
use lightning_types::payment::PaymentHash;

use crate::fee_estimator::{ConfirmationTarget, FeeEstimator, OnchainFeeEstimator};
use crate::logger::{log_error, log_trace, LdkLogger};
use crate::types::{ChannelManager, KeysManager, LiquidityManager, PeerManager, Wallet};
use crate::{total_anchor_channels_reserve_sats, Config};

const LSPS2_GETINFO_REQUEST_EXPIRY: Duration = Duration::from_secs(60 * 60 * 48);
const LSPS2_CHANNEL_CLTV_EXPIRY_DELTA: u32 = 72;

pub(crate) struct LSPS2Service {
	pub(crate) service_config: LSPS2ServiceConfig,
	pub(crate) ldk_service_config: LdkLSPS2ServiceConfig,
}

pub(crate) struct LSPS2ServiceLiquiditySource<L: Deref>
where
	L::Target: LdkLogger,
{
	pub(crate) lsps2_service: Option<LSPS2Service>,
	pub(crate) wallet: Arc<Wallet>,
	pub(crate) fee_estimator: Arc<OnchainFeeEstimator>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) peer_manager: RwLock<Option<Weak<PeerManager>>>,
	pub(crate) keys_manager: Arc<KeysManager>,
	pub(crate) liquidity_manager: Arc<LiquidityManager>,
	pub(crate) config: Arc<Config>,
	pub(crate) logger: L,
}

/// Represents the configuration of the LSPS2 service.
///
/// See [bLIP-52 / LSPS2] for more information.
///
/// [bLIP-52 / LSPS2]: https://github.com/lightning/blips/blob/master/blip-0052.md
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LSPS2ServiceConfig {
	/// A token we may require to be sent by the clients.
	///
	/// If set, only requests matching this token will be accepted.
	pub require_token: Option<String>,
	/// Indicates whether the LSPS service will be announced via the gossip network.
	pub advertise_service: bool,
	/// The fee we withhold for the channel open from the initial payment.
	///
	/// This fee is proportional to the client-requested amount, in parts-per-million.
	pub channel_opening_fee_ppm: u32,
	/// The proportional overprovisioning for the channel.
	///
	/// This determines, in parts-per-million, how much value we'll provision on top of the amount
	/// we need to forward the payment to the client.
	///
	/// For example, setting this to `100_000` will result in a channel being opened that is 10%
	/// larger than then the to-be-forwarded amount (i.e., client-requested amount minus the
	/// channel opening fee fee).
	pub channel_over_provisioning_ppm: u32,
	/// The minimum fee required for opening a channel.
	pub min_channel_opening_fee_msat: u64,
	/// The minimum number of blocks after confirmation we promise to keep the channel open.
	pub min_channel_lifetime: u32,
	/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
	pub max_client_to_self_delay: u32,
	/// The minimum payment size that we will accept when opening a channel.
	pub min_payment_size_msat: u64,
	/// The maximum payment size that we will accept when opening a channel.
	pub max_payment_size_msat: u64,
	/// Use the 'client-trusts-LSP' trust model.
	///
	/// When set, the service will delay *broadcasting* the JIT channel's funding transaction until
	/// the client claimed sufficient HTLC parts to pay for the channel open.
	///
	/// Note this will render the flow incompatible with clients utilizing the 'LSP-trust-client'
	/// trust model, i.e., in turn delay *claiming* any HTLCs until they see the funding
	/// transaction in the mempool.
	///
	/// Please refer to [`bLIP-52`] for more information.
	///
	/// [`bLIP-52`]: https://github.com/lightning/blips/blob/master/blip-0052.md#trust-models
	pub client_trusts_lsp: bool,
	/// When set, we will allow clients to spend their entire channel balance in the channels
	/// we open to them. This allows clients to try to steal your channel balance with
	/// no financial penalty, so this should only be set if you trust your clients.
	///
	/// See [`Node::open_0reserve_channel`] to manually open these channels.
	///
	/// [`Node::open_0reserve_channel`]: crate::Node::open_0reserve_channel
	pub disable_client_reserve: bool,
}

impl<L: Deref> LSPS2ServiceLiquiditySource<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn set_peer_manager(&self, peer_manager: Weak<PeerManager>) {
		*self.peer_manager.write().expect("lock") = Some(peer_manager);
	}

	pub(crate) fn liquidity_manager(&self) -> Arc<LiquidityManager> {
		Arc::clone(&self.liquidity_manager)
	}

	pub(crate) fn lsps2_channel_needs_manual_broadcast(
		&self, counterparty_node_id: PublicKey, user_channel_id: u128,
	) -> bool {
		self.lsps2_service.as_ref().map_or(false, |lsps2_service| {
			lsps2_service.service_config.client_trusts_lsp
				&& self
					.liquidity_manager()
					.lsps2_service_handler()
					.and_then(|handler| {
						handler
							.channel_needs_manual_broadcast(user_channel_id, &counterparty_node_id)
							.ok()
					})
					.unwrap_or(false)
		})
	}

	pub(crate) fn lsps2_store_funding_transaction(
		&self, user_channel_id: u128, counterparty_node_id: PublicKey, funding_tx: Transaction,
	) {
		let Some(lsps2_service) = self.lsps2_service.as_ref() else { return };
		if !lsps2_service.service_config.client_trusts_lsp {
			// Only necessary for client-trusts-LSP flow
			return;
		}

		let lsps2_service_handler = self.liquidity_manager.lsps2_service_handler();
		if let Some(handler) = lsps2_service_handler {
			handler
				.store_funding_transaction(user_channel_id, &counterparty_node_id, funding_tx)
				.unwrap_or_else(|e| {
					debug_assert!(false, "Failed to store funding transaction: {:?}", e);
					log_error!(self.logger, "Failed to store funding transaction: {:?}", e);
				});
		} else {
			log_error!(self.logger, "LSPS2 service handler is not available.");
		}
	}

	pub(crate) fn lsps2_funding_tx_broadcast_safe(
		&self, user_channel_id: u128, counterparty_node_id: PublicKey,
	) {
		let Some(lsps2_service) = self.lsps2_service.as_ref() else { return };
		if !lsps2_service.service_config.client_trusts_lsp {
			// Only necessary for client-trusts-LSP flow
			return;
		}

		let lsps2_service_handler = self.liquidity_manager.lsps2_service_handler();
		if let Some(handler) = lsps2_service_handler {
			handler
				.set_funding_tx_broadcast_safe(user_channel_id, &counterparty_node_id)
				.unwrap_or_else(|e| {
					debug_assert!(
						false,
						"Failed to mark funding transaction safe to broadcast: {:?}",
						e
					);
					log_error!(
						self.logger,
						"Failed to mark funding transaction safe to broadcast: {:?}",
						e
					);
				});
		} else {
			log_error!(self.logger, "LSPS2 service handler is not available.");
		}
	}

	pub(crate) async fn handle_channel_ready(
		&self, user_channel_id: u128, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
	) {
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler
				.channel_ready(user_channel_id, channel_id, counterparty_node_id)
				.await
			{
				log_error!(
					self.logger,
					"LSPS2 service failed to handle ChannelReady event: {:?}",
					e
				);
			}
		}
	}

	pub(crate) async fn handle_htlc_intercepted(
		&self, intercept_scid: u64, intercept_id: InterceptId, expected_outbound_amount_msat: u64,
		payment_hash: PaymentHash, inbound_amount_msat: u64,
	) {
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler
				.htlc_intercepted(
					intercept_scid,
					intercept_id,
					expected_outbound_amount_msat,
					payment_hash,
					inbound_amount_msat,
				)
				.await
			{
				log_error!(
					self.logger,
					"LSPS2 service failed to handle HTLCIntercepted event: {:?}",
					e
				);
			}
		}
	}

	pub(crate) async fn handle_htlc_handling_failed(&self, failure_type: HTLCHandlingFailureType) {
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler.htlc_handling_failed(failure_type).await {
				log_error!(
					self.logger,
					"LSPS2 service failed to handle HTLCHandlingFailed event: {:?}",
					e
				);
			}
		}
	}

	pub(crate) async fn handle_payment_forwarded(
		&self, next_channel_id: Option<ChannelId>, skimmed_fee_msat: u64,
	) {
		if let Some(next_channel_id) = next_channel_id {
			if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
				if let Err(e) =
					lsps2_service_handler.payment_forwarded(next_channel_id, skimmed_fee_msat).await
				{
					log_error!(
						self.logger,
						"LSPS2 service failed to handle PaymentForwarded: {:?}",
						e
					);
				}
			}
		}
	}

	pub(crate) async fn handle_channel_closed(
		&self, user_channel_id: u128, channel_id: ChannelId, counterparty_node_id: &PublicKey,
	) {
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			// A JIT channel closing before it became ready is a failed channel open. This errors
			// for any channel that isn't such a JIT channel, which is the common case.
			if let Err(e) = lsps2_service_handler
				.channel_open_failed(counterparty_node_id, user_channel_id)
				.await
			{
				log_trace!(
					self.logger,
					"LSPS2 service did not treat the closure of channel {} as a failed channel open: {:?}",
					channel_id,
					e
				);
			}

			if let Err(e) = lsps2_service_handler.channel_closed(channel_id).await {
				log_error!(
					self.logger,
					"LSPS2 service failed to handle ChannelClosed event: {:?}",
					e
				);
			}
		}
	}

	/// Fails the HTLCs held for the given JIT channel back, allowing the payer to retry.
	async fn fail_channel_open(&self, counterparty_node_id: &PublicKey, user_channel_id: u128) {
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler
				.channel_open_failed(counterparty_node_id, user_channel_id)
				.await
			{
				log_error!(
					self.logger,
					"LSPS2 service failed to handle failed channel open: {:?}",
					e
				);
			}
		}
	}

	pub(crate) async fn handle_event(&self, event: LSPS2ServiceEvent) {
		match event {
			LSPS2ServiceEvent::GetInfo { request_id, counterparty_node_id, token } => {
				if let Some(lsps2_service_handler) =
					self.liquidity_manager.lsps2_service_handler().as_ref()
				{
					let service_config = if let Some(service_config) =
						self.lsps2_service.as_ref().map(|s| s.service_config.clone())
					{
						service_config
					} else {
						log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
						return;
					};

					if let Some(required) = service_config.require_token {
						if token != Some(required) {
							log_error!(
								self.logger,
								"Rejecting LSPS2 request {:?} from counterparty {} as the client provided an invalid token.",
								request_id,
								counterparty_node_id
							);
							lsps2_service_handler.invalid_token_provided(&counterparty_node_id, request_id.clone()).unwrap_or_else(|e| {
								debug_assert!(false, "Failed to reject LSPS2 request. This should never happen.");
								log_error!(
									self.logger,
									"Failed to reject LSPS2 request {:?} from counterparty {} due to: {:?}. This should never happen.",
									request_id,
									counterparty_node_id,
									e
								);
							});
							return;
						}
					}

					let valid_until = LSPSDateTime(Utc::now() + LSPS2_GETINFO_REQUEST_EXPIRY);
					let opening_fee_params = LSPS2RawOpeningFeeParams {
						min_fee_msat: service_config.min_channel_opening_fee_msat,
						proportional: service_config.channel_opening_fee_ppm,
						valid_until,
						min_lifetime: service_config.min_channel_lifetime,
						max_client_to_self_delay: service_config.max_client_to_self_delay,
						min_payment_size_msat: service_config.min_payment_size_msat,
						max_payment_size_msat: service_config.max_payment_size_msat,
					};

					let opening_fee_params_menu = vec![opening_fee_params];

					if let Err(e) = lsps2_service_handler.opening_fee_params_generated(
						&counterparty_node_id,
						request_id,
						opening_fee_params_menu,
					) {
						log_error!(
							self.logger,
							"Failed to handle generated opening fee params: {:?}",
							e
						);
					}
				} else {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				}
			},
			LSPS2ServiceEvent::BuyRequest {
				request_id,
				counterparty_node_id,
				opening_fee_params: _,
				payment_size_msat,
			} => {
				if let Some(lsps2_service_handler) =
					self.liquidity_manager.lsps2_service_handler().as_ref()
				{
					let service_config = if let Some(service_config) =
						self.lsps2_service.as_ref().map(|s| s.service_config.clone())
					{
						service_config
					} else {
						log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
						return;
					};

					let user_channel_id: u128 = u128::from_ne_bytes(
						self.keys_manager.get_secure_random_bytes()[..16]
							.try_into()
							.expect("a 16-byte slice should convert into a [u8; 16]"),
					);
					let intercept_scid = self.channel_manager.get_intercept_scid();

					if let Some(payment_size_msat) = payment_size_msat {
						// We already check this in `lightning-liquidity`, but better safe than
						// sorry.
						//
						// TODO: We might want to eventually send back an error here, but we
						// currently can't and have to trust `lightning-liquidity` is doing the
						// right thing.
						//
						// TODO: Eventually we also might want to make sure that we have sufficient
						// liquidity for the channel opening here.
						if payment_size_msat > service_config.max_payment_size_msat
							|| payment_size_msat < service_config.min_payment_size_msat
						{
							log_error!(
								self.logger,
								"Rejecting to handle LSPS2 buy request {:?} from counterparty {} as the client requested an invalid payment size.",
								request_id,
								counterparty_node_id
							);
							return;
						}
					}

					match lsps2_service_handler
						.invoice_parameters_generated(
							&counterparty_node_id,
							request_id,
							intercept_scid,
							LSPS2_CHANNEL_CLTV_EXPIRY_DELTA,
							service_config.client_trusts_lsp,
							user_channel_id,
						)
						.await
					{
						Ok(()) => {},
						Err(e) => {
							log_error!(
								self.logger,
								"Failed to provide invoice parameters: {:?}",
								e
							);
							return;
						},
					}
				} else {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				}
			},
			LSPS2ServiceEvent::OpenChannel {
				their_network_key,
				amt_to_forward_msat,
				opening_fee_msat: _,
				user_channel_id,
				intercept_scid: _,
			} => {
				if self.liquidity_manager.lsps2_service_handler().is_none() {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				};

				let service_config = if let Some(service_config) =
					self.lsps2_service.as_ref().map(|s| s.service_config.clone())
				{
					service_config
				} else {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				};

				let peer_manager = self
					.peer_manager
					.read()
					.expect("lock")
					.as_ref()
					.and_then(|weak| weak.upgrade());
				let Some(peer_manager) = peer_manager else {
					debug_assert!(false, "Failed to handle LSPS2ServiceEvent as peer manager isn't available. This should never happen.",);
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as peer manager isn't available. This should never happen.",);
					return;
				};

				// Fail if we're not connected to the prospective channel partner.
				let Some(peer) = peer_manager.peer_by_node_id(&their_network_key) else {
					log_error!(
						self.logger,
						"Failed to open LSPS2 channel to {} due to peer not being connected.",
						their_network_key,
					);
					// TODO: We fail the payment back here. Eventually we will need to remember
					// the pending requests and regularly retry opening the channel until we
					// succeed.
					self.fail_channel_open(&their_network_key, user_channel_id).await;
					return;
				};
				let init_features = peer.init_features;

				// Fail if we have insufficient onchain funds available.
				let over_provisioning_msat = amt_to_forward_msat
					.saturating_mul(service_config.channel_over_provisioning_ppm as u64)
					/ 1_000_000;
				let channel_amount_sats =
					amt_to_forward_msat.saturating_add(over_provisioning_msat) / 1000;
				let cur_anchor_reserve_sats =
					total_anchor_channels_reserve_sats(&self.channel_manager, &self.config);
				let spendable_amount_sats =
					self.wallet.get_spendable_amount_sats(cur_anchor_reserve_sats).unwrap_or(0);
				let anchor_channel =
					crate::peer_may_negotiate_anchor_channel_type(&self.config, &init_features);
				let additional_reserve_required = crate::new_channel_anchor_reserve_sats(
					&self.config,
					&their_network_key,
					anchor_channel,
				);
				let required_funds_sats =
					channel_amount_sats.saturating_add(additional_reserve_required);
				if spendable_amount_sats < required_funds_sats {
					log_error!(self.logger,
						"Unable to create channel due to insufficient funds. Available: {}sats, Required: {}sats",
						spendable_amount_sats, required_funds_sats,
					);
					// TODO: We fail the payment back here. Eventually we will need to remember
					// the pending requests and regularly retry opening the channel until we
					// succeed.
					self.fail_channel_open(&their_network_key, user_channel_id).await;
					return;
				}

				// The funding transaction's fee is paid from the same on-chain funds, so we can't
				// fund more than we would when opening a channel with all of them.
				let total_anchor_reserve_sats =
					cur_anchor_reserve_sats.saturating_add(additional_reserve_required);
				let funding_fee_rate =
					self.fee_estimator.estimate_fee_rate(ConfirmationTarget::ChannelFunding);
				let max_amount = match self
					.wallet
					.get_max_funding_amount(total_anchor_reserve_sats, funding_fee_rate)
				{
					Ok(max_amount) => max_amount,
					Err(e) => {
						log_error!(
							self.logger,
							"Unable to create channel as the maximum funding amount couldn't be determined: {:?}",
							e,
						);
						self.fail_channel_open(&their_network_key, user_channel_id).await;
						return;
					},
				};
				if channel_amount_sats > max_amount {
					log_error!(self.logger,
						"Unable to create channel due to insufficient funds. Requested: {}sats, Maximum: {}sats (fee rate: {} sat/kw, anchor reserve: {}sats)",
						channel_amount_sats, max_amount, funding_fee_rate.to_sat_per_kwu(), total_anchor_reserve_sats,
					);
					self.fail_channel_open(&their_network_key, user_channel_id).await;
					return;
				}

				let mut config = self.channel_manager.get_current_config().clone();

				// If we act as an LSPS2 service, the HTLC-value-in-flight must be 100% of the
				// channel value to ensure we can forward the initial payment. That cap only
				// applies to unannounced channels, so the channel must also be unannounced.
				debug_assert_eq!(
					config
						.channel_handshake_config
						.unannounced_channel_max_inbound_htlc_value_in_flight_percentage,
					100
				);
				debug_assert!(!config.channel_handshake_config.announce_for_forwarding);
				debug_assert!(config.accept_forwards_to_priv_channels);

				// We set the forwarding fee to 0 for now as we're getting paid by the channel fee.
				//
				// TODO: revisit this decision eventually.
				config.channel_config.forwarding_fee_base_msat = 0;
				config.channel_config.forwarding_fee_proportional_millionths = 0;

				let result = if service_config.disable_client_reserve {
					self.channel_manager.create_channel_to_trusted_peer_0reserve(
						their_network_key,
						channel_amount_sats,
						0,
						user_channel_id,
						None,
						Some(config),
					)
				} else {
					self.channel_manager.create_channel(
						their_network_key,
						channel_amount_sats,
						0,
						user_channel_id,
						None,
						Some(config),
					)
				};

				match result {
					Ok(_) => {},
					Err(e) => {
						let zero_reserve_string =
							if service_config.disable_client_reserve { "0reserve " } else { "" };
						log_error!(
							self.logger,
							"Failed to open LSPS2 {}channel to {}: {:?}",
							zero_reserve_string,
							their_network_key,
							e
						);
						// TODO: We fail the payment back here. Eventually we will need to remember
						// the pending requests and regularly retry opening the channel until we
						// succeed.
						self.fail_channel_open(&their_network_key, user_channel_id).await;
						return;
					},
				}
			},
		}
	}
}

/// How the LSPS2 service provides the liquidity for a buy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Not yet acted on: the `OpenChannel` handler always opens.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum JitLiquidityPlan {
	/// Open a new channel to the client.
	Open(OpenReason),
	/// Splice the liquidity into this channel with the client.
	Splice(ChannelId),
	/// Wait for this channel with the client to become usable, then plan again.
	WaitFor(ChannelId),
}

/// Why a buy is served by opening a new channel rather than by a splice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum OpenReason {
	/// No channel can carry the amount to forward, now or once it is usable. A splice does not
	/// raise the client's `max_htlc_value_in_flight_msat`, which LDK fixes at the channel's open.
	AboveHtlcMaximum,
	/// The client did not signal `option_splice` in its `init` message.
	ClientLacksSplicing,
	/// The client-trusts-LSP model withholds the funding transaction until the client claims,
	/// but LDK broadcasts a splice transaction as soon as `tx_signatures` are exchanged.
	ClientTrustsLsp,
	/// We have no channel with the client that is not shutting down.
	NoChannel,
}

/// A channel with the client, as far as splicing a buy into it is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ClientChannel {
	pub(crate) channel_id: ChannelId,
	pub(crate) channel_value_sats: u64,
	pub(crate) state: ClientChannelState,
}

/// Where a channel with the client stands for splicing.
///
/// The HTLC maximum is [`ChannelCounterparty::outbound_htlc_maximum_msat`]: the smaller of the
/// client's `max_htlc_value_in_flight_msat` and the channel's value less both reserves. A splice
/// raises only the latter, and LDK does not expose the former, so the maximum is a lower bound on
/// what the channel carries after a splice.
///
/// [`ChannelCounterparty::outbound_htlc_maximum_msat`]: lightning::ln::channel_state::ChannelCounterparty::outbound_htlc_maximum_msat
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ClientChannelState {
	/// The channel is not yet usable, e.g., as its funding awaits `channel_ready` or the peer is
	/// reestablishing it. The HTLC maximum is known once the client accepted the channel.
	Pending { outbound_htlc_maximum_msat: Option<u64> },
	/// A `shutdown` was sent or received for the channel.
	ShuttingDown,
	/// The channel is usable, with `outbound_htlcs_msat` of HTLCs to the client in flight, which
	/// count against the same maximum.
	Usable { outbound_htlc_maximum_msat: u64, outbound_htlcs_msat: u64 },
}

/// Chooses how to provide the liquidity for a buy forwarding `amt_to_forward_msat` to a client
/// we have `channels` with.
///
/// A client that can't be spliced with, as it lacks `option_splice` or the service uses the
/// client-trusts-LSP model, gets a new channel. Otherwise we splice into a usable channel with
/// room for the payment and wait for a pending channel that may have room, rather than open a
/// second channel beside it. Among several, we prefer the largest and then the lowest channel id.
/// We open a new channel when no channel exists or none can carry the payment.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn plan_jit_liquidity(
	client_supports_splicing: bool, client_trusts_lsp: bool, amt_to_forward_msat: u64,
	channels: &[ClientChannel],
) -> JitLiquidityPlan {
	if channels.iter().all(|channel| channel.state == ClientChannelState::ShuttingDown) {
		return JitLiquidityPlan::Open(OpenReason::NoChannel);
	}
	if !client_supports_splicing {
		return JitLiquidityPlan::Open(OpenReason::ClientLacksSplicing);
	}
	if client_trusts_lsp {
		return JitLiquidityPlan::Open(OpenReason::ClientTrustsLsp);
	}

	let preference =
		|channel: &&ClientChannel| (channel.channel_value_sats, Reverse(channel.channel_id));
	let has_room = |channel: &&ClientChannel| match channel.state {
		ClientChannelState::Usable { outbound_htlc_maximum_msat, outbound_htlcs_msat } => {
			outbound_htlc_maximum_msat.saturating_sub(outbound_htlcs_msat) >= amt_to_forward_msat
		},
		ClientChannelState::Pending { .. } | ClientChannelState::ShuttingDown => false,
	};
	let may_have_room = |channel: &&ClientChannel| match channel.state {
		ClientChannelState::Pending { outbound_htlc_maximum_msat } => {
			outbound_htlc_maximum_msat.map_or(true, |maximum| maximum >= amt_to_forward_msat)
		},
		ClientChannelState::ShuttingDown | ClientChannelState::Usable { .. } => false,
	};

	if let Some(channel) = channels.iter().filter(has_room).max_by_key(preference) {
		return JitLiquidityPlan::Splice(channel.channel_id);
	}
	if let Some(channel) = channels.iter().filter(may_have_room).max_by_key(preference) {
		return JitLiquidityPlan::WaitFor(channel.channel_id);
	}
	JitLiquidityPlan::Open(OpenReason::AboveHtlcMaximum)
}

#[cfg(test)]
mod tests {
	use super::*;

	const AMOUNT_MSAT: u64 = 50_000_000;

	fn usable(id: u8, channel_value_sats: u64) -> ClientChannel {
		with_state(
			id,
			channel_value_sats,
			ClientChannelState::Usable {
				outbound_htlc_maximum_msat: channel_value_sats * 1000,
				outbound_htlcs_msat: 0,
			},
		)
	}

	fn pending(id: u8, channel_value_sats: u64) -> ClientChannel {
		let outbound_htlc_maximum_msat = Some(channel_value_sats * 1000);
		with_state(
			id,
			channel_value_sats,
			ClientChannelState::Pending { outbound_htlc_maximum_msat },
		)
	}

	fn with_state(id: u8, channel_value_sats: u64, state: ClientChannelState) -> ClientChannel {
		ClientChannel { channel_id: ChannelId([id; 32]), channel_value_sats, state }
	}

	fn plan(channels: &[ClientChannel]) -> JitLiquidityPlan {
		plan_jit_liquidity(true, false, AMOUNT_MSAT, channels)
	}

	#[test]
	fn a_client_without_a_channel_gets_one_opened() {
		assert_eq!(plan(&[]), JitLiquidityPlan::Open(OpenReason::NoChannel));
	}

	#[test]
	fn a_channel_shutting_down_is_not_spliced_into() {
		let closing = with_state(1, 100_000, ClientChannelState::ShuttingDown);
		assert_eq!(plan(&[closing]), JitLiquidityPlan::Open(OpenReason::NoChannel));
	}

	#[test]
	fn a_usable_channel_with_room_for_the_payment_is_spliced_into() {
		let channel = usable(1, 100_000);
		assert_eq!(plan(&[channel]), JitLiquidityPlan::Splice(channel.channel_id));
	}

	#[test]
	fn a_client_without_option_splice_gets_a_channel_opened() {
		assert_eq!(
			plan_jit_liquidity(false, false, AMOUNT_MSAT, &[usable(1, 100_000)]),
			JitLiquidityPlan::Open(OpenReason::ClientLacksSplicing)
		);
	}

	#[test]
	fn a_client_without_option_splice_gets_a_channel_opened_beside_a_pending_one() {
		assert_eq!(
			plan_jit_liquidity(false, false, AMOUNT_MSAT, &[pending(1, 100_000)]),
			JitLiquidityPlan::Open(OpenReason::ClientLacksSplicing)
		);
	}

	#[test]
	fn the_client_trusts_lsp_model_opens_a_channel() {
		assert_eq!(
			plan_jit_liquidity(true, true, AMOUNT_MSAT, &[usable(1, 100_000)]),
			JitLiquidityPlan::Open(OpenReason::ClientTrustsLsp)
		);
	}

	#[test]
	fn a_payment_above_the_htlc_maximum_opens_a_channel() {
		let channel = with_state(
			1,
			1_000_000,
			ClientChannelState::Usable {
				outbound_htlc_maximum_msat: AMOUNT_MSAT - 1,
				outbound_htlcs_msat: 0,
			},
		);
		assert_eq!(plan(&[channel]), JitLiquidityPlan::Open(OpenReason::AboveHtlcMaximum));
	}

	#[test]
	fn a_payment_at_the_htlc_maximum_is_spliced() {
		let channel = with_state(
			1,
			1_000_000,
			ClientChannelState::Usable {
				outbound_htlc_maximum_msat: AMOUNT_MSAT,
				outbound_htlcs_msat: 0,
			},
		);
		assert_eq!(plan(&[channel]), JitLiquidityPlan::Splice(channel.channel_id));
	}

	#[test]
	fn htlcs_in_flight_count_against_the_htlc_maximum() {
		let channel = with_state(
			1,
			1_000_000,
			ClientChannelState::Usable {
				outbound_htlc_maximum_msat: AMOUNT_MSAT,
				outbound_htlcs_msat: 1,
			},
		);
		assert_eq!(plan(&[channel]), JitLiquidityPlan::Open(OpenReason::AboveHtlcMaximum));
	}

	#[test]
	fn a_channel_not_yet_usable_is_waited_for() {
		let channel = pending(1, 100_000);
		assert_eq!(plan(&[channel]), JitLiquidityPlan::WaitFor(channel.channel_id));
	}

	#[test]
	fn a_channel_not_yet_accepted_is_waited_for() {
		let channel = with_state(
			1,
			100_000,
			ClientChannelState::Pending { outbound_htlc_maximum_msat: None },
		);
		assert_eq!(plan(&[channel]), JitLiquidityPlan::WaitFor(channel.channel_id));
	}

	#[test]
	fn a_pending_channel_too_small_for_the_payment_is_not_waited_for() {
		let channel = with_state(
			1,
			100_000,
			ClientChannelState::Pending { outbound_htlc_maximum_msat: Some(AMOUNT_MSAT - 1) },
		);
		assert_eq!(plan(&[channel]), JitLiquidityPlan::Open(OpenReason::AboveHtlcMaximum));
	}

	#[test]
	fn a_usable_channel_is_spliced_into_before_one_not_yet_usable_is_waited_for() {
		let channel = usable(2, 100_000);
		assert_eq!(
			plan(&[pending(1, 1_000_000), channel]),
			JitLiquidityPlan::Splice(channel.channel_id)
		);
	}

	#[test]
	fn a_channel_not_yet_usable_is_waited_for_when_no_usable_one_has_room() {
		let full = with_state(
			1,
			1_000_000,
			ClientChannelState::Usable {
				outbound_htlc_maximum_msat: AMOUNT_MSAT - 1,
				outbound_htlcs_msat: 0,
			},
		);
		let channel = pending(2, 100_000);
		assert_eq!(plan(&[full, channel]), JitLiquidityPlan::WaitFor(channel.channel_id));
	}

	#[test]
	fn the_largest_usable_channel_is_spliced_into() {
		let (small, large) = (usable(1, 100_000), usable(2, 200_000));
		assert_eq!(plan(&[small, large]), JitLiquidityPlan::Splice(large.channel_id));
		assert_eq!(plan(&[large, small]), JitLiquidityPlan::Splice(large.channel_id));
	}

	#[test]
	fn among_equal_channels_the_lowest_channel_id_is_spliced_into() {
		let (low, high) = (usable(1, 100_000), usable(2, 100_000));
		assert_eq!(plan(&[high, low]), JitLiquidityPlan::Splice(low.channel_id));
		assert_eq!(plan(&[low, high]), JitLiquidityPlan::Splice(low.channel_id));
	}

	#[test]
	fn among_channels_not_yet_usable_the_largest_is_waited_for() {
		let (small, large) = (pending(1, 100_000), pending(2, 200_000));
		assert_eq!(plan(&[small, large]), JitLiquidityPlan::WaitFor(large.channel_id));
	}
}
