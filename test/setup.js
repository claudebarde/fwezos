const Fwezos = artifacts.require("Fwezos");
const { Tezos } = require("@taquito/taquito");
const { InMemorySigner } = require("@taquito/signer");
const { alice } = require("../scripts/sandbox/accounts");

let storage, fwezos_address, fwezos_instance;

const signerFactory = async pk => {
  await Tezos.setProvider({ signer: new InMemorySigner(pk) });
  return Tezos;
};

module.exports = async () => {
  fwezos_instance = await Fwezos.deployed();
  // this code bypasses Truffle config to be able to have different signers
  // until I find how to do it directly with Truffle
  await Tezos.setProvider({ rpc: "http://localhost:8732" });
  await signerFactory(alice.sk);
  /**
   * Display the current contract address for debugging purposes
   */
  console.log("Contract deployed at:", fwezos_instance.address);
  fwezos_address = fwezos_instance.address;
  fwezos_instance = await Tezos.contract.at(fwezos_instance.address);
  storage = await fwezos_instance.storage();

  return {
    storage,
    fwezos_address,
    fwezos_instance,
    signerFactory
  };
};
