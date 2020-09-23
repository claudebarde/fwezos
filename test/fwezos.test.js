const { MichelsonMap, Tezos } = require("@taquito/taquito");
const { alice, bob } = require("../scripts/sandbox/accounts");
const setup = require("./setup");

contract("Pixel Art NFT Contract", () => {
  let storage;
  let fwezos_address;
  let fwezos_instance;
  let signerFactory;

  before(async () => {
    const config = await setup();
    storage = config.storage;
    fwezos_address = config.fwezos_address;
    fwezos_instance = config.fwezos_instance;
    signerFactory = config.signerFactory;
    Tezos.setRpcProvider("http://localhost:8732");
  });

  it("Alice should be the admin", async () => {
    assert.equal(alice.pkh, storage.admin);
  });

  it("should mint 20 fwezos for Alice", async () => {
    const amount = 20 * 10 ** 6;
    try {
      const op = await fwezos_instance.methods
        .mint_tokens([["unit"]])
        .send({ amount, mutez: true });
      await op.confirmation();
      // checks 20 tokens have been minted for Alice
      storage = await fwezos_instance.storage();
      const balance = await storage.ledger.get(alice.pkh);
      assert.equal(amount / 10 ** 6, balance.toNumber());
      // checks the contract balance is XTZ 20
      const contractBalance = await Tezos.tz.getBalance(fwezos_address);
      assert.equal(amount, contractBalance.toNumber());
    } catch (error) {
      console.log(error);
    }
  });

  it("should let Alice withdraw half of her fwezos", async () => {
    const tokens = await storage.ledger.get(alice.pkh);
    const aliceBalance = await Tezos.tz.getBalance(alice.pkh);
    const contractBalance = await Tezos.tz.getBalance(fwezos_address);

    try {
      const op = await fwezos_instance.methods
        .redeem_tokens(Math.round(tokens.toNumber() / 2))
        .send();
      await op.confirmation();
      // confirms balances have been updated
      storage = await fwezos_instance.storage();
      const aliceNewBalance = await Tezos.tz.getBalance(alice.pkh);
      const newTokens = await storage.ledger.get(alice.pkh);
      const contractNewBalance = await Tezos.tz.getBalance(fwezos_address);

      assert.equal(newTokens, tokens / 2);
      assert.equal(
        contractNewBalance.toNumber(),
        contractBalance.toNumber() / 2
      );
      assert.isAbove(aliceNewBalance.toNumber(), aliceBalance.toNumber());
    } catch (error) {
      console.log(error);
    }
  });
});
