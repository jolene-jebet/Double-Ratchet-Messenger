'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

//sending public keys in JSON text. turns the text back into a key we can use 
// We send public keys as JSON text. This turns that text back into a key we can use.
const { subtle } = require('node:crypto').webcrypto
async function importPublicKey (jwk) {
  return await subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-384' }, true, [])
}


class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
    async generateCertificate (username) {
    // 1. Make my long-term key pair (my secret colour + my public mixture)
    this.EGKeyPair = await generateEG()

    // 2. Make my ID card: my name + my public key.
    //    The key is saved as JSON text so the CA's stamp covers the real key.
    //    (A key object turns into "{}" when the card is stringified.)
    const certificate = {
      username: username,
      pub: await cryptoKeyToJSON(this.EGKeyPair.pub)
    }
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)

    // Check the CA's stamp on the ID card
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!isValid) {
      throw new Error('Fake or tampered certificate!')
    }

    // The stamp is real, so save the card under the person's name
    this.certs[certificate.username] = certificate
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
    async sendMessage (name, plaintext) {
    // STEP 1: First message to this person? Set up the conversation.
    if (!this.conns[name]) {
      const theirPub = await importPublicKey(this.certs[name].pub)

      // Starting secret: my secret + their public key (Bob can make the same one)
      const startSecret = await computeDH(this.EGKeyPair.sec, theirPub)

      // A fresh ratchet key pair for me, mixed with their key = a new secret
      const myKeys = await generateEG()
      const newSecret = await computeDH(myKeys.sec, theirPub)

      // Big ratchet click: HKDF mixes the new secret into the starting secret
      // and gives back two keys: a new root key and my first sending chain key
      const out = await HKDF(newSecret, startSecret, 'ratchet-str')

      this.conns[name] = {
        myKeys: myKeys, // my current ratchet key pair
        theirPub: this.certs[name].pub, // their current ratchet public key (JSON)
        rootKey: out[0],
        sendChain: out[1],
        recvChain: null,
        sendCount: 0, // ticket number of my next message
        recvCount: 0 // ticket number I expect from them next
      }
    }
    const conn = this.conns[name]

    // STEP 2: Small ratchet click (the blender): a brand-new key for this message
    const messageKey = await HMACtoAESKey(conn.sendChain, 'message-key') // locks the message
    const messageKeyBytes = await HMACtoAESKey(conn.sendChain, 'message-key', true) // same key as raw bytes, for the government
    conn.sendChain = await HMACtoHMACKey(conn.sendChain, 'chain-key') // next chain key; the old one is gone

    // STEP 3: Government's spare-key box (ElGamal)
    const oneOffKeys = await generateEG() // one-off key pair just for this message
    const govSecret = await computeDH(oneOffKeys.sec, this.govPublicKey) // mix with the government's public key
    const govKey = await HMACtoAESKey(govSecret, govEncryptionDataStr) // turn it into a key that can lock things
    const ivGov = genRandomSalt()
    const cGov = await encryptWithGCM(govKey, messageKeyBytes, ivGov) // lock the copy of the message key

    // STEP 4: The header = the writing on the outside of the envelope
    const header = {
      dh: await cryptoKeyToJSON(conn.myKeys.pub), // my current ratchet public key
      count: conn.sendCount, // ticket number
      vGov: oneOffKeys.pub, // the government needs this to open the box
      cGov: cGov, // the locked copy of the message key
      ivGov: ivGov,
      receiverIV: genRandomSalt() // random sticker for the real message
    }
    conn.sendCount += 1

    // STEP 5: Lock the message. The header is passed as "authenticated data",
    // so it sits under the wax seal: readable, but it can't be changed.
    const ciphertext = await encryptWithGCM(messageKey, plaintext, header.receiverIV, JSON.stringify(header))
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
   async receiveMessage (name, [header, ciphertext]) {
    // STEP 1: First message from this person? Set up the conversation.
    if (!this.conns[name]) {
      const theirPub = await importPublicKey(this.certs[name].pub)
      this.conns[name] = {
        myKeys: this.EGKeyPair, // my ID-card key pair is my first ratchet key
        theirPub: null, // I haven't seen their ratchet key yet
        rootKey: await computeDH(this.EGKeyPair.sec, theirPub), // the same starting secret Alice made
        sendChain: null,
        recvChain: null,
        sendCount: 0,
        recvCount: 0
      }
    }

    // Work on a copy. We only save it at the end, if the message opens.
    // So a fake message can't mess up our keys.
    const conn = { ...this.conns[name] }

    // STEP 2: A new ratchet key in the header means they changed speaker:
    // click the big ratchet.
    if (JSON.stringify(header.dh) !== JSON.stringify(conn.theirPub)) {
      conn.theirPub = header.dh
      const theirKey = await importPublicKey(header.dh)

      // (a) My key + their new key -> new root key + my receiving chain
      const secret1 = await computeDH(conn.myKeys.sec, theirKey)
      const out1 = await HKDF(secret1, conn.rootKey, 'ratchet-str')
      conn.rootKey = out1[0]
      conn.recvChain = out1[1]

      // (b) A brand-new key pair for my next reply -> new root key + my sending chain
      conn.myKeys = await generateEG()
      const secret2 = await computeDH(conn.myKeys.sec, theirKey)
      const out2 = await HKDF(secret2, conn.rootKey, 'ratchet-str')
      conn.rootKey = out2[0]
      conn.sendChain = out2[1]

      // New chains, so the ticket numbers start again
      conn.sendCount = 0
      conn.recvCount = 0
    }

    // STEP 3: Ticket check: is this exactly the message number I expect?
    if (header.count !== conn.recvCount) {
      throw new Error('Message replayed, dropped or out of order!')
    }

    // STEP 4: Small ratchet click on my receiving chain (same blender as Alice's)
    const messageKey = await HMACtoAESKey(conn.recvChain, 'message-key')
    conn.recvChain = await HMACtoHMACKey(conn.recvChain, 'chain-key')

    // STEP 5: Unlock. decryptWithGCM throws an error by itself if the message
    // or the header was changed, or if it wasn't meant for me.
    const plaintext = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, JSON.stringify(header))

    // It opened, so save the new keys (the old ones are gone)
    conn.recvCount += 1
    this.conns[name] = conn
    return bufferToString(plaintext)
  }
};

module.exports = {
  MessengerClient
}
