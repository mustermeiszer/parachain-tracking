// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transaction storage pallet. Indexes transactions and manages storage proofs.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod benchmarking;
pub mod weights;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    dispatch::{Dispatchable, GetDispatchInfo},
    traits::{Currency, OnUnbalanced, ReservableCurrency},
};
use sp_runtime::traits::{BlakeTwo256, Hash, One, Saturating, Zero};
use sp_std::{prelude::*, result};
use sp_transaction_storage_proof::{
    encode_index, random_chunk, InherentError, TransactionStorageProof, CHUNK_SIZE,
    INHERENT_IDENTIFIER,
};

/// A type alias for the balance type from this pallet's point of view.
type BalanceOf<T> =
<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;
pub use weights::WeightInfo;

/// Maximum bytes that can be stored in one transaction.
// Setting higher limit also requires raising the allocator limit.
pub const DEFAULT_MAX_TRANSACTION_SIZE: u32 = 8 * 1024 * 1024;

/// State data for a stored transaction.
#[derive(
Encode,
Decode,
Clone,
sp_runtime::RuntimeDebug,
PartialEq,
Eq,
scale_info::TypeInfo,
MaxEncodedLen,
)]
pub struct TransactionInfo {
    /// Chunk trie root.
    chunk_root: <BlakeTwo256 as Hash>::Output,
    /// Plain hash of indexed data.
    content_hash: <BlakeTwo256 as Hash>::Output,
    /// Size of indexed data in bytes.
    size: u32,
    /// Total number of chunks added in the block with this transaction. This
    /// is used find transaction info by block chunk index using binary search.
    block_chunks: u32,
}

fn num_chunks(bytes: u32) -> u32 {
    ((bytes as u64 + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as u32
}

pub enum Chain {
    Relay,
    Para(ParaId),
}

pub struct Provable<MaxData: Get<u32>, MaxTrieNodes: Get<u32>, MaxTrieNodeSize: Get<u32>>
{
    data: BoundedVec<u8, MaxData>,
    proof: BoundedVec<BoundedVec<u8, MaxTrieNodeSize>, MaxTrieNodes>
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The para ids that the chain wants to track
        type Paras: GetKey<ParaId>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Proof failed verification.
        InvalidProof,
        /// Missing storage proof.
        MissingProof,
        /// Transaction is too large.
        ProofTooLarge,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: T::BlockNumber) -> Weight {
            assert!(

            );
        }

        fn on_finalize(n: T::BlockNumber) {
            assert!(

            );
        }
    }

    ///
    #[pallet::storage]
    #[pallet::getter(fn lates_relay_head)]
    type LatestRelayHead<T: Config> = StorageValue<
        _,
        Hash,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn relay_head)]
    type RelayHead<T: Config> = StorageMap<
        _,
        Index,
        Hash,
        OptionQuery,
    >;

    #[pallet::storage]
    type RelayHeadToIndex<T: Config> = StorageeMap<
        _,
        Twox128_Concat,
        Hash,
        Index,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn para_head)]
    type ParaHead<T: Config> = StorageDoubleMap<
        _,
        Twox128_Concat,
        ParaId,
        Twox128_Concat,
        Index,
        Hash,
        OptionQuery,
    >;

    #[pallet::storage]
    type ParaHeadToIndex<T: Config> = StorageDoubleMap<
        _,
        Twox128_Concat,
        ParaId,
        Twox128_Concat,
        Hash,
        Index,
        OptionQuery,
    >;


    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        pub fn remark(origin: OriginFor<T>, chain: Chain, provable: Provable) -> DispatchResult {
            Ok(())
        }

        #[pallet::weight((T::WeightInfo::check_proof_max(), DispatchClass::Mandatory))]
        pub fn set_parachain_head(
            origin: OriginFor<T>,
            parachain: ParaId,
            provable: Provable
        ) -> DispatchResultWithPostInfo {
            ensure_none(origin)?;
            ensure!(!ProofChecked::<T>::get(), Error::<T>::DoubleCheck);
            let number = <frame_system::Pallet<T>>::block_number();
            let period = <StoragePeriod<T>>::get();
            let target_number = number.saturating_sub(period);
            ensure!(!target_number.is_zero(), Error::<T>::UnexpectedProof);
            let total_chunks = <ChunkCount<T>>::get(target_number);
            ensure!(total_chunks != 0, Error::<T>::UnexpectedProof);
            let parent_hash = <frame_system::Pallet<T>>::parent_hash();
            let selected_chunk_index = random_chunk(parent_hash.as_ref(), total_chunks);
            let (info, chunk_index) = match <Transactions<T>>::get(target_number) {
                Some(infos) => {
                    let index = match infos
                        .binary_search_by_key(&selected_chunk_index, |info| info.block_chunks)
                    {
                        Ok(index) => index,
                        Err(index) => index,
                    };
                    let info = infos.get(index).ok_or(Error::<T>::MissingStateData)?.clone();
                    let chunks = num_chunks(info.size);
                    let prev_chunks = info.block_chunks - chunks;
                    (info, selected_chunk_index - prev_chunks)
                },
                None => return Err(Error::<T>::MissingStateData.into()),
            };
            ensure!(
				sp_io::trie::blake2_256_verify_proof(
					info.chunk_root,
					&proof.proof,
					&encode_index(chunk_index),
					&proof.chunk,
					sp_runtime::StateVersion::V1,
				),
				Error::<T>::InvalidProof
			);
            ProofChecked::<T>::put(true);
            Self::deposit_event(Event::ProofChecked);
            Ok(().into())
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Stored data under specified index.
        Stored { index: u32 },
        /// Renewed data under specified index.
        Renewed { index: u32 },
        /// Storage proof was successfully checked.
        ProofChecked,
    }

    /// Collection of transaction metadata by block number.
    #[pallet::storage]
    #[pallet::getter(fn transaction_roots)]
    pub(super) type Transactions<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::BlockNumber,
        BoundedVec<TransactionInfo, T::MaxBlockTransactions>,
        OptionQuery,
    >;

    /// Count indexed chunks for each block.
    #[pallet::storage]
    pub(super) type ChunkCount<T: Config> =
    StorageMap<_, Blake2_128Concat, T::BlockNumber, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn byte_fee)]
    /// Storage fee per byte.
    pub(super) type ByteFee<T: Config> = StorageValue<_, BalanceOf<T>>;

    #[pallet::storage]
    #[pallet::getter(fn entry_fee)]
    /// Storage fee per transaction.
    pub(super) type EntryFee<T: Config> = StorageValue<_, BalanceOf<T>>;

    /// Storage period for data in blocks. Should match `sp_storage_proof::DEFAULT_STORAGE_PERIOD`
    /// for block authoring.
    #[pallet::storage]
    pub(super) type StoragePeriod<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

    // Intermediates
    #[pallet::storage]
    pub(super) type BlockTransactions<T: Config> =
    StorageValue<_, BoundedVec<TransactionInfo, T::MaxBlockTransactions>, ValueQuery>;

    /// Was the proof checked in this block?
    #[pallet::storage]
    pub(super) type ProofChecked<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub byte_fee: BalanceOf<T>,
        pub entry_fee: BalanceOf<T>,
        pub storage_period: T::BlockNumber,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                byte_fee: 10u32.into(),
                entry_fee: 1000u32.into(),
                storage_period: sp_transaction_storage_proof::DEFAULT_STORAGE_PERIOD.into(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            <ByteFee<T>>::put(&self.byte_fee);
            <EntryFee<T>>::put(&self.entry_fee);
            <StoragePeriod<T>>::put(&self.storage_period);
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            let proof = data
                .get_data::<TransactionStorageProof>(&Self::INHERENT_IDENTIFIER)
                .unwrap_or(None);
            proof.map(|proof| Call::check_proof { proof })
        }

        fn check_inherent(
            _call: &Self::Call,
            _data: &InherentData,
        ) -> result::Result<(), Self::Error> {
            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::check_proof { .. })
        }
    }

    impl<T: Config> Pallet<T> {
        fn apply_fee(sender: T::AccountId, size: u32) -> DispatchResult {
            let byte_fee = ByteFee::<T>::get().ok_or(Error::<T>::NotConfigured)?;
            let entry_fee = EntryFee::<T>::get().ok_or(Error::<T>::NotConfigured)?;
            let fee = byte_fee.saturating_mul(size.into()).saturating_add(entry_fee);
            ensure!(T::Currency::can_slash(&sender, fee), Error::<T>::InsufficientFunds);
            let (credit, _) = T::Currency::slash(&sender, fee);
            T::FeeDestination::on_unbalanced(credit);
            Ok(())
        }
    }
}
