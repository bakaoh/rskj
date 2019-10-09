package co.rsk.peg;

import co.rsk.bitcoinj.core.*;
import co.rsk.bitcoinj.script.ScriptBuilder;
import co.rsk.bitcoinj.store.BlockStoreException;
import co.rsk.config.BridgeConstants;
import co.rsk.config.BridgeRegTestConstants;
import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import co.rsk.db.MutableTrieCache;
import co.rsk.db.MutableTrieImpl;
import co.rsk.peg.utils.BridgeEventLogger;
import co.rsk.peg.whitelist.LockWhitelist;
import co.rsk.peg.whitelist.OneOffWhiteListEntry;
import co.rsk.trie.Trie;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;
import org.ethereum.core.Block;
import org.ethereum.core.Repository;
import org.ethereum.core.Transaction;
import org.ethereum.crypto.HashUtil;
import org.ethereum.db.MutableRepository;
import org.ethereum.vm.PrecompiledContracts;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.mock;

public class BridgeSupportTest {
    private static final co.rsk.core.Coin LIMIT_MONETARY_BASE = new co.rsk.core.Coin(new BigInteger("21000000000000000000000000"));

    @Test
    public void getLockingCap() {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP134)).thenReturn(true);

        BridgeConstants constants = mock(BridgeConstants.class);
        when(constants.getInitialLockingCap()).thenReturn(Coin.SATOSHI);

        BridgeStorageProvider provider = mock(BridgeStorageProvider.class);
        when(provider.getLockingCap()).thenReturn(null).thenReturn(constants.getInitialLockingCap());

        BridgeSupport bridgeSupport = getBridgeSupport(
                constants, provider, mock(Repository.class), null, null, null, activations
        );

        // First time should also call setLockingCap as it was null
        assertEquals(constants.getInitialLockingCap(), bridgeSupport.getLockingCap());
        // Second time should just return the value
        assertEquals(constants.getInitialLockingCap(), bridgeSupport.getLockingCap());
        // Verify the set was called just once
        verify(provider, times(1)).setLockingCap(constants.getInitialLockingCap());
    }

    @Test
    public void increaseLockingCap_unauthorized() {
        AddressBasedAuthorizer authorizer = mock(AddressBasedAuthorizer.class);
        when(authorizer.isAuthorized(any(Transaction.class))).thenReturn(false);

        BridgeConstants constants = mock(BridgeConstants.class);
        when(constants.getIncreaseLockingCapAuthorizer()).thenReturn(authorizer);

        BridgeSupport bridgeSupport = getBridgeSupport(
                constants, mock(BridgeStorageProvider.class)
        );

        assertFalse(bridgeSupport.increaseLockingCap(mock(Transaction.class), Coin.SATOSHI));
    }

    @Test
    public void increaseLockingCap_invalidValue() {
        BridgeStorageProvider provider = mock(BridgeStorageProvider.class);
        when(provider.getLockingCap()).thenReturn(Coin.COIN);

        AddressBasedAuthorizer authorizer = mock(AddressBasedAuthorizer.class);
        when(authorizer.isAuthorized(any(Transaction.class))).thenReturn(true);

        BridgeConstants constants = mock(BridgeConstants.class);
        when(constants.getIncreaseLockingCapAuthorizer()).thenReturn(authorizer);

        BridgeSupport bridgeSupport = getBridgeSupport(
                constants, provider
        );

        assertFalse(bridgeSupport.increaseLockingCap(mock(Transaction.class), Coin.SATOSHI));
    }

    @Test
    public void increaseLockingCap() {
        BridgeStorageProvider provider = mock(BridgeStorageProvider.class);
        when(provider.getLockingCap()).thenReturn(Coin.SATOSHI);

        AddressBasedAuthorizer authorizer = mock(AddressBasedAuthorizer.class);
        when(authorizer.isAuthorized(any(Transaction.class))).thenReturn(true);

        BridgeConstants constants = mock(BridgeConstants.class);
        when(constants.getIncreaseLockingCapAuthorizer()).thenReturn(authorizer);

        BridgeSupport bridgeSupport = getBridgeSupport(
                constants, provider
        );

        assertTrue(bridgeSupport.increaseLockingCap(mock(Transaction.class), Coin.COIN));
    }

    @Test
    public void registerBtcTransaction_aboveLockingCap_newFed_beforeRSKIP134Activation() throws IOException, BlockStoreException {
        assertLockingCap(false, true, true);
    }

    @Test
    public void registerBtcTransaction_aboveLockingCap_oldFed_beforeRSKIP134Activation() throws IOException, BlockStoreException {
        assertLockingCap(false, false, true);
    }

    @Test
    public void registerBtcTransaction_aboveLockingCap_newFed_afterRSKIP134Activation() throws IOException, BlockStoreException {
        assertLockingCap(true, true, true);
    }

    @Test
    public void registerBtcTransaction_aboveLockingCap_oldFed_afterRSKIP134Activation() throws IOException, BlockStoreException {
        assertLockingCap(true, false, true);
    }

    @Test
    public void registerBtcTransaction_belowLockingCap_newFed_afterRSKIP134Activation() throws IOException, BlockStoreException {
        assertLockingCap(true, true, false);
    }

    @Test
    public void registerBtcTransaction_belowLockingCap_oldFed_afterRSKIP134Activation() throws IOException, BlockStoreException {
        assertLockingCap(true, false, false);
    }

    private BridgeSupport getBridgeSupport(BridgeConstants constants, BridgeStorageProvider provider) {
        return getBridgeSupport(constants, provider, null, null, null, null);
    }

    private BridgeSupport getBridgeSupport(BridgeConstants constants, BridgeStorageProvider provider, Repository track,
                                           BridgeEventLogger eventLogger, Block executionBlock,
                                           BtcBlockStoreWithCache.Factory blockStoreFactory) {
        return getBridgeSupport(
                constants, provider, track, eventLogger, executionBlock,
                blockStoreFactory, mock(ActivationConfig.ForBlock.class)
        );
    }

    private BridgeSupport getBridgeSupport(BridgeConstants constants, BridgeStorageProvider provider, Repository track,
                                           BridgeEventLogger eventLogger, Block executionBlock,
                                           BtcBlockStoreWithCache.Factory blockStoreFactory,
                                           ActivationConfig.ForBlock activations) {
        if (eventLogger == null) {
            eventLogger = mock(BridgeEventLogger.class);
        }
        if (blockStoreFactory == null) {
            blockStoreFactory = mock(BtcBlockStoreWithCache.Factory.class);
        }
        return new BridgeSupport(
                constants, provider, eventLogger, track, executionBlock,
                new Context(constants.getBtcParams()),
                new FederationSupport(constants, provider, executionBlock),
                blockStoreFactory, activations
        );
    }

    private Repository createRepository() {
        return new MutableRepository(new MutableTrieCache(new MutableTrieImpl(null, new Trie())));
    }

    private void assertLockingCap(boolean isLockingCapEnabled, boolean useNewFederation, boolean sendsAboveLockingCap) throws BlockStoreException, IOException {

        BridgeStorageConfiguration bsConfiguration =
                new BridgeStorageConfiguration(false, false, isLockingCapEnabled);
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP134)).thenReturn(isLockingCapEnabled);

        BridgeConstants bridgeConstants = mock(BridgeConstants.class);
        when(bridgeConstants.getMinimumLockTxValue()).thenReturn(Coin.SATOSHI);
        when(bridgeConstants.getBtcParams()).thenReturn(BridgeRegTestConstants.getInstance().getBtcParams());
        when(bridgeConstants.getBtc2RskMinimumAcceptableConfirmations()).thenReturn(1);
        when(bridgeConstants.getGenesisFeePerKb()).thenReturn(BridgeRegTestConstants.getInstance().getGenesisFeePerKb());
        // Force the initial locking cap to 1 BTC
        when(bridgeConstants.getInitialLockingCap()).thenReturn(Coin.COIN);

        Repository repository = createRepository();
        // Fund bridge
        repository.addBalance(PrecompiledContracts.BRIDGE_ADDR, LIMIT_MONETARY_BASE);
        Repository track = repository.startTracking();

        Federation federation = this.getFederation(bridgeConstants, null);

        // Send 50BTC or 0.0001BTC depending on the configuration
        Coin lockValue = sendsAboveLockingCap ? Coin.FIFTY_COINS : Coin.MILLICOIN;

        // Create transaction
        BtcTransaction tx = new BtcTransaction(bridgeConstants.getBtcParams());
        tx.addOutput(lockValue, federation.getAddress());
        BtcECKey srcKey = new BtcECKey();
        tx.addInput(PegTestUtils.createHash(1), 0, ScriptBuilder.createInputScript(null, srcKey));

        // Create header and PMT
        byte[] bits = new byte[1];
        bits[0] = 0x3f;
        List<Sha256Hash> hashes = new ArrayList<>();
        hashes.add(tx.getHash());
        PartialMerkleTree pmt = new PartialMerkleTree(bridgeConstants.getBtcParams(), bits, hashes, 1);
        Sha256Hash merkleRoot = pmt.getTxnHashAndMerkleRoot(new ArrayList<>());
        co.rsk.bitcoinj.core.BtcBlock registerHeader =
                new co.rsk.bitcoinj.core.BtcBlock(bridgeConstants.getBtcParams(), 1, PegTestUtils.createHash(), merkleRoot,
                        1, 1, 1, new ArrayList<BtcTransaction>());

        BtcBlockStoreWithCache btcBlockStore = mock(BtcBlockStoreWithCache.class);
        BtcBlockStoreWithCache.Factory mockFactory = mock(BtcBlockStoreWithCache.Factory.class);
        when(mockFactory.newInstance(track)).thenReturn(btcBlockStore);

        Block executionBlock = Mockito.mock(Block.class);
        when(executionBlock.getNumber()).thenReturn(10L);

        BridgeStorageProvider provider =
                new BridgeStorageProvider(track, PrecompiledContracts.BRIDGE_ADDR, bridgeConstants, bsConfiguration);
        if (useNewFederation) {
            provider.setNewFederation(federation);
        } else {
            // We need a random new fed
            provider.setNewFederation(this.getFederation(bridgeConstants,
                    Arrays.asList(new BtcECKey[]{
                        BtcECKey.fromPrivate(Hex.decode("fb01")),
                        BtcECKey.fromPrivate(Hex.decode("fb02")),
                        BtcECKey.fromPrivate(Hex.decode("fb03")),
                    })
            ));
            provider.setOldFederation(federation);
        }

        // Get the tx sender public key
        byte[] data = tx.getInput(0).getScriptSig().getChunks().get(1).data;
        BtcECKey senderBtcKey = BtcECKey.fromPublicOnly(data);

        // Whitelist the addresses
        LockWhitelist whitelist = provider.getLockWhitelist();
        Address address = senderBtcKey.toAddress(bridgeConstants.getBtcParams());
        whitelist.put(address, new OneOffWhiteListEntry(address, lockValue));
        // The address is whitelisted
        Assert.assertThat(whitelist.isWhitelisted(address), is(true));

        BridgeSupport bridgeSupport = getBridgeSupport(bridgeConstants, provider, track, null, executionBlock, mockFactory, activations);

        // Simulate blockchain
        int height = 1;
        mockChainOfStoredBlocks(btcBlockStore, registerHeader, height + bridgeConstants.getBtc2RskMinimumAcceptableConfirmations(), height);

        Transaction rskTx = mock(Transaction.class);
        Keccak256 hash = new Keccak256(HashUtil.keccak256(new byte[] {}));
        when(rskTx.getHash()).thenReturn(hash);

        // Try to register tx
        bridgeSupport.registerBtcTransaction(rskTx, tx.bitcoinSerialize(), height, pmt.bitcoinSerialize());
        bridgeSupport.save();

        track.commit();

        // If the address is no longer whitelisted, it means it was consumed, whether the lock was rejected by lockingCap or not
        Assert.assertThat(whitelist.isWhitelisted(address), is(false));

        boolean shouldHaveLocked = !isLockingCapEnabled || isLockingCapEnabled && !sendsAboveLockingCap;

        co.rsk.core.Coin totalAmountExpectedToHaveBeenLocked = co.rsk.core.Coin.fromBitcoin(shouldHaveLocked ? lockValue : Coin.ZERO);
        RskAddress srcKeyRskAddress = new RskAddress(org.ethereum.crypto.ECKey.fromPrivate(srcKey.getPrivKey()).getAddress());

        // Verify amount was locked
        Assert.assertEquals(totalAmountExpectedToHaveBeenLocked, repository.getBalance(srcKeyRskAddress));
        Assert.assertEquals(LIMIT_MONETARY_BASE.subtract(totalAmountExpectedToHaveBeenLocked), repository.getBalance(PrecompiledContracts.BRIDGE_ADDR));

        if (!shouldHaveLocked) {
            // Release tx should have been created directly to the signatures stack
            BtcTransaction releaseTx = provider.getRskTxsWaitingForSignatures().get(hash);
            Assert.assertNotNull(releaseTx);
            // returns the funds to the sender
            Assert.assertEquals(1, releaseTx.getOutputs().size());
            Assert.assertEquals(address, releaseTx.getOutputs().get(0).getAddressFromP2PKHScript(bridgeConstants.getBtcParams()));
            Assert.assertEquals(lockValue, releaseTx.getOutputs().get(0).getValue().add(releaseTx.getFee()));
            // Uses the same UTXO
            Assert.assertEquals(1, releaseTx.getInputs().size());
            Assert.assertEquals(tx.getHash(), releaseTx.getInputs().get(0).getOutpoint().getHash());
            Assert.assertEquals(0, releaseTx.getInputs().get(0).getOutpoint().getIndex());
        }
    }

    private void mockChainOfStoredBlocks(BtcBlockStoreWithCache btcBlockStore, BtcBlock targetHeader, int headHeight, int targetHeight) throws BlockStoreException {
        // Simulate that the block is in there by mocking the getter by height,
        // and then simulate that the txs have enough confirmations by setting a high head.
        when(btcBlockStore.getStoredBlockAtMainChainHeight(targetHeight)).thenReturn(new StoredBlock(targetHeader, BigInteger.ONE, targetHeight));
        // Mock current pointer's header
        StoredBlock currentStored = mock(StoredBlock.class);
        BtcBlock currentBlock = mock(BtcBlock.class);
        doReturn(Sha256Hash.of(Hex.decode("aa"))).when(currentBlock).getHash();
        doReturn(currentBlock).when(currentStored).getHeader();
        when(currentStored.getHeader()).thenReturn(currentBlock);
        when(btcBlockStore.getChainHead()).thenReturn(currentStored);
        when(currentStored.getHeight()).thenReturn(headHeight);

    }

    private Federation getFederation(BridgeConstants bridgeConstants, List<BtcECKey> fedKeys) {
        List<BtcECKey> defaultFederationKeys = Arrays.asList(new BtcECKey[]{
                BtcECKey.fromPrivate(Hex.decode("fa01")),
                BtcECKey.fromPrivate(Hex.decode("fa02")),
        });
        List<BtcECKey> federationKeys = fedKeys ==  null ? defaultFederationKeys : fedKeys;
        federationKeys.sort(BtcECKey.PUBKEY_COMPARATOR);

        return new Federation(
                FederationTestUtils.getFederationMembersWithBtcKeys(federationKeys),
                Instant.ofEpochMilli(1000L), 0L, bridgeConstants.getBtcParams());
    }
}
