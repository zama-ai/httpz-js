import { bytesToBigInt, fromHexString } from '../utils';
import {
  u8vec_to_cryptobox_pk,
  new_client,
  process_reencryption_resp_from_js,
  u8vec_to_cryptobox_sk,
} from 'node-tkms';
import { ethers, getAddress } from 'ethers';

const aclABI = [
  'function persistAllowed(uint256 handle, address account) view returns (bool)',
];

export type CtHandleContractPair = {
  ctHandle: bigint;
  contractAddress: string;
};

export type RequestValidity = {
  /// @notice The start timestamp of the user decryption request
  startTimestamp: bigint;
  /// @notice The duration in days for the user decryption to be processed
  durationDays: bigint;
};

export const userDecryptRequest =
  (
    kmsSignatures: string[],
    chainId: number,
    kmsContractAddress: string,
    aclContractAddress: string,
    relayerUrl: string,
    provider: ethers.JsonRpcProvider | ethers.BrowserProvider,
  ) =>
  async (
    handles: CtHandleContractPair[],
    privateKey: string,
    publicKey: string,
    signature: string,
    contractAddresses: string[],
    userAddress: string,
    startTimestamp: RequestValidity['startTimestamp'],
    durationDays: RequestValidity['durationDays'],
  ): Promise<bigint[]> => {
    const acl = new ethers.Contract(aclContractAddress, aclABI, provider);
    const verifications = handles.map(async ({ ctHandle, contractAddress }) => {
      const userAllowed = await acl.persistAllowed(ctHandle, userAddress);
      const contractAllowed = await acl.persistAllowed(
        ctHandle,
        contractAddress,
      );
      if (!userAllowed) {
        throw new Error('User is not authorized to reencrypt this handle!');
      }
      if (!contractAllowed) {
        throw new Error(
          'dApp contract is not authorized to reencrypt this handle!',
        );
      }
      if (userAddress === contractAddress) {
        throw new Error(
          'userAddress should not be equal to contractAddress when requesting reencryption!',
        );
      }
    });

    Promise.all(verifications).catch((e) => {
      throw e;
    });

    /*

    	@curl -X POST http://127.0.0.1:3000/user-decrypt \
-H "Content-Type: application/json" \
-d '{"signature": "cEc0e9723bF28D2A2C867108cC4C3A38a011d4D1",
    "userAddress": "0xcEc0e9723bF28D2A2C867108cC4C3A38a011d4D1",
    "enc_key": "a5e1defb98EFe38EBb2D958CEe052410247F4c80",
    "ct_handle": "a5e1defb98EFe38EBb2D958CEe052410247F4c802410247F4c8010247F4c8076",
    "contractAddress": "0xa5e1defb98EFe38EBb2D958CEe052410247F4c80",
    "chainId": "1234"}'

     CtHandleContractPair[] calldata ctHandleContractPairs,
        RequestValidity calldata requestValidity,
        uint256 contractsChainId,
        address[] calldata contractAddresses,
        address userAddress,
        bytes calldata publicKey,
        bytes calldata signature
    */
    const payloadForRequest = {
      ctHandleContractPairs: handles.map((h) => {
        return {
          ctHandle: h.ctHandle.toString(16).padStart(64, '0'),
          contractAddress: h.contractAddress,
        };
      }),
      requestValidity: {
        startTimestamp: startTimestamp.toString(), // Convert to string
        durationDays: durationDays.toString(), // Convert to string
      },
      contractsChainId: chainId.toString(), // Convert to string
      contractAddresses: contractAddresses.map((c) => getAddress(c)),
      userAddress: getAddress(userAddress),
      signature: signature.replace(/^(0x)/, ''),
      publicKey: publicKey.replace(/^(0x)/, ''),
    };
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payloadForRequest),
    };
    let pubKey;
    let privKey;
    try {
      pubKey = u8vec_to_cryptobox_pk(fromHexString(publicKey));
      privKey = u8vec_to_cryptobox_sk(fromHexString(privateKey));
    } catch (e) {
      throw new Error('Invalid public or private key', { cause: e });
    }
    console.log(options);

    let response;
    let json;
    try {
      response = await fetch(`${relayerUrl}user-decrypt`, options);
      if (!response.ok) {
        throw new Error(
          `Reencrypt failed: relayer respond with HTTP code ${response.status}`,
        );
      }
    } catch (e) {
      throw new Error("Reencrypt failed: Relayer didn't respond", { cause: e });
    }

    try {
      json = await response.json();
    } catch (e) {
      throw new Error("Reencrypt failed: Relayer didn't return a JSON", {
        cause: e,
      });
    }

    if (json.status === 'failure') {
      throw new Error(
        "Reencrypt failed: the reencryption didn't succeed for an unknown reason",
        { cause: json },
      );
    }

    const client = new_client(kmsSignatures, userAddress, 'default');

    try {
      const buffer = new ArrayBuffer(32);
      const view = new DataView(buffer);
      view.setUint32(28, chainId, false);
      const chainIdArrayBE = new Uint8Array(buffer);
      const eip712Domain = {
        name: 'Authorization token',
        version: '1',
        chain_id: chainIdArrayBE,
        verifying_contract: kmsContractAddress,
        salt: null,
      };
      // Duplicate payloadForRequest and replace ciphertext_handle with ciphertext_digest.
      // TODO check all ciphertext digests are all the same
      const payloadForVerification = {
        signature,
        client_address: userAddress,
        enc_key: pubKey,
        ciphertext_handles: handles.map((h) => h.ctHandle),
        eip712_verifying_contract: kmsContractAddress,
      };

      const decryption = process_reencryption_resp_from_js(
        client,
        payloadForVerification,
        eip712Domain,
        json.response,
        pubKey,
        privKey,
        true,
      );

      return decryption.map((d) => bytesToBigInt(d.bytes));
    } catch (e) {
      throw new Error('An error occured during decryption', { cause: e });
    }
  };
