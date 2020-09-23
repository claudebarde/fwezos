const Fwezos = artifacts.require("Fwezos");
const { MichelsonMap } = require("@taquito/taquito");
const { alice } = require("../scripts/sandbox/accounts");

const initialStorage = {
  admin: alice.pkh,
  ledger: new MichelsonMap(),
  operators: new MichelsonMap(),
  token_metadata: MichelsonMap.fromLiteral({
    0: {
      token_id: 0,
      symbol: "FWZ",
      name: "Fwezos",
      decimals: 0,
      extras: new MichelsonMap()
    }
  }),
  total_supply: 0
};

module.exports = async (deployer, _network, accounts) => {
  deployer.deploy(Fwezos, initialStorage);
};
