## Whisper API Overview

This is a summary of all functions that are available to the ÐApp developpers.

### version

Returns the Whisper version this node offers.

geth console call:

<pre><code> > shh.version
</code></pre>

### info

Returns the Whisper statistics for diagnostics.

geth console call:

<pre><code> > shh.info
</code></pre>

### setMaxMessageSize

Sets the maximal message length allowed by this node.

geth console call:

<pre><code> > shh.setMaxMessageSize(999999)
</code></pre>

### setMinPow

Sets the minimal PoW required by this node.

geth console call:

<pre><code> > shh.setMinPoW(2.12)
</code></pre>

### markTrustedPeer

Marks specific peer trusted, which will allow it to send historic (expired) messages.

geth console call:

<pre><code> > shh.markTrustedPeer("enode://d25474361659861e9e651bc728a17e807a3359ca0d344afd544ed0f11a31faecaf4d74b55db53c6670fd624f08d5c79adfc8da5dd4a11b9213db49a3b750845e@52.178.209.125:30379")

</code></pre>

### hasKeyPair

Checks if the whisper node is configured with the private key of the specified public pair.

geth console call:

<pre><code> > shh.hasKeyPair("5e57b9ffc2387e18636e0a3d0c56b023264c16e78a2adcba1303cefc685e610f")
</code></pre>

### deleteKeyPair

Deletes the specifies key if it exists.

geth console call:

<pre><code> > shh.deleteKeyPair("5e57b9ffc2387e18636e0a3d0c56b023264c16e78a2adcba1303cefc685e610f")
</code></pre>

### newKeyPair

Generates a new cryptographic identity for the client, and injects it into the known identities for message decryption.

geth console call:

<pre><code> > shh.newKeyPair()
</code></pre>

### getPublicKey

Returns the public key for identity id.

geth console call:

<pre><code> > shh.getPublicKey("86e658cbc6da63120b79b5eec0c67d5dcfb6865a8f983eff08932477282b77bb")
</code></pre>

### getPrivateKey

Returns the private key for identity id.

geth console call:

<pre><code> > shh.getPrivateKey("86e658cbc6da63120b79b5eec0c67d5dcfb6865a8f983eff08932477282b77bb")
</code></pre>

### newSymKey

Generates a random symmetric key and stores it under id, which is then returned. Will be used in the future for session key exchange.

geth console call:

<pre><code> > shh.newSymKey()
</code></pre>

### addSymKey

Stores the key, and returns its id.

geth console call:

<pre><code> > shh.addSymKey("0xf6dcf21ed6a17bd78d8c4c63195ab997b3b65ea683705501eae82d32667adc92")
</code></pre>

### generateSymKeyFromPassword

Generates the key from password, stores it, and returns its id.

geth console call:

<pre><code> > shh.generateSymKeyFromPassword("test")
</code></pre>

### getSymKey

Returns the symmetric key associated with the given id.

geth console call:

<pre><code> > shh.getSymKey("f6dcf21ed6a17bd78d8c4c63195ab997b3b65ea683705501eae82d32667adc92")
</code></pre>

### hasSymKey

Returns true if there is a key associated with the name string. Otherwise, returns false.

geth console call:

<pre><code> > shh.hasSymKey("f6dcf21ed6a17bd78d8c4c63195ab997b3b65ea683705501eae82d32667adc92")
</code></pre>

### deleteSymKey

Deletes the key associated with the name string if it exists.

geth console call:

<pre><code> > shh.deleteSymKey("f6dcf21ed6a17bd78d8c4c63195ab997b3b65ea683705501eae82d32667adc92")
</code></pre>

### getFilterMessages

Retrieves all the new messages matched by a filter since the last retrieval.

geth console call:

<pre><code> > shh.getFilterMessages("02c1f5c953804acee3b68eda6c0afe3f1b4e0bec73c7445e10d45da333616412")
</code></pre>

### newMessageFilter

Creates and registers a new message filter to watch for inbound whisper messages. 
Returns the ID of the newly created Filter.
Please see parameter description below.

geth console call:

<pre><code> > shh.newMessageFilter({pow: 12.3, topics: ['0x5a4ea131', '0x11223344'], pubKey: 'b874f3bbaf031214a567485b703a025cec27d26b2c4457d6b139e56ad8734cea', sig: '0x048229fb947363cf13bb9f9532e124f08840cd6287ecae6b537cda2947ec2b23dbdc3a07bdf7cd2bfb288c25c4d0d0461d91c719da736a22b7bebbcf912298d1e6'})
</code></pre>

### deleteMessageFilter

Disables and removes an existing filter.

geth console call:

<pre><code> > shh.deleteMessageFilter("02c1f5c953804acee3b68eda6c0afe3f1b4e0bec73c7445e10d45da333616412")
</code></pre>

### Post

Creates a whisper message and injects it into the network for distribution.
Please see parameter description below.

geth console call:

<pre><code> > shh.post({ttl: 7, topic: '0x07678231', powTarget: 2.01, powTime: 2, payload: '0x68656c6c6f', pubKey: '0x048229fb947363cf13bb9f9532e124f08840cd6287ecae6b537cda2947ec2b23dbdc3a07bdf7cd2bfb288c25c4d0d0461d91c719da736a22b7bebbcf912298d1e6'})
</code></pre>

<hr>

### Parameters of NewMessageFilter

<pre><code>func (self *PublicWhisperAPI) NewMessageFilter(req Criteria) (string, error)
</code></pre>

The argument of Subscribe function is a JSON object with the following format:

	symKeyID   string
	pubKey     []byte
	sig        string
	minPoW     float64
	topics     [][]byte
	allowP2P   bool

symKeyID: When using symmetric key encryption, holds the symmetric key ID.

pubKey: When using asymmetric key encryption, holds the public key.

key: ID of the decryption key (symmetric or asymmetric).

sig: Public key of the signature.

minPoW: Minimal PoW requirement for incoming messages.

topics: Array of possible topics (or partial topics).

allowP2P: Indicates if this filter allows processing of direct peer-to-peer messages (which are not to be forwarded any further, because they might be expired). This might be the case in some very rare cases, e.g. if you intend to communicate to MailServers, etc.

### Parameters of Post

<pre><code>func (self *PublicWhisperAPI) Post(args PostArgs) error
</code></pre>

The argument of Post function is a JSON object with the following format:

	symKeyID   string
	pubKey     []byte
	sig        string
	ttl        uint32
	topic      [4]byte
	padding    []byte
	payload    []byte
	powTime    uint32
	powTarget  float64
	targetPeer string
	
symKeyID: When using symmetric key encryption, holds the symmetric key ID.

pubKey: When using asymmetric key encryption, holds the public key.

ttl: Time-to-live in seconds.

sig: ID of the signing key.

topic: Message topic (four bytes of arbitrary data).

payload: Payload to be encrypted.

padding: Optional padding (byte array of arbitrary length).

powTime: Maximal time in seconds to be spent on prrof of work.

powTarget: Minimal PoW target required for this message.

targetPeer: Optional peer ID (for peer-to-peer message only).

## Usage

Every node should treat all the messages equally, including those generated by the node itself. Therefore most users might subscribe for certain messages before sending their own. After subscription is complete, users might call GetMessages if they want to intercept the floating messages that match a the newly installed subscription filter. It might be necessary to install the encryption keys prior to subscription.

### Testing the Whisper node (geth) on private network

In order to connect to private network you need to know the enode of the bootstrap node. As of today (April 28, 2017) we have a test node with the following enode:
enode://d25474361659861e9e651bc728a17e807a3359ca0d344afd544ed0f11a31faecaf4d74b55db53c6670fd624f08d5c79adfc8da5dd4a11b9213db49a3b750845e@52.178.209.125:30379

Alternatively, you can run the diagnostic tool (wnode) as bootstrap node:

	> wnode -forwarder -standalone
	
More info on wnode tool you can find in a separate document [here](https://github.com/ethereum/go-ethereum/wiki/Whisper).

Start your geth with the following parameters:

	> geth --shh --testnet --nodiscover console
	
Then connect to the bootstrap node, e.g.:
	admin.addPeer("enode://0f7f440d473c92e3734e5b93e30eb131f5a065a3673b0d191481267e777e508884ae6bd9d1aca3b995bc5044917248009877488c30f7fdd7c2f63823e4dd55dc@127.0.0.1:30379")

Now you can start playing with Whisper using geth.

### Use Cases

Below you will find several examples which illustrate the sequence of events in different scenarios. 
Each geth console command is followed by the corresponding result output, if it is relevant.

#### Receive Asymmetrically Encrypted Messages

Generate a key pair, and save its ID.

	> id = shh.newKeyPair()
	"46af9c31a30c2eeb4e6fbb5d02a0b64b62d147e576f1503372a02d4f80ebb4e1"

Retrieve and save your public key.

	> shh.getPublicKey('46af9c31a30c2eeb4e6fbb5d02a0b64b62d147e576f1503372a02d4f80ebb4e1')
	"0x048d7938066b4fb9465879c837762a767648e9473e0a6a470d719f71024d4a59450b2151b303b5f90ea35fd2e8cd91968783da17add12973e9867c626750bae3e9"

Subcribe to messages, encrypted with certain public key.
In this case we create the simplest possible subscription:

	> f = shh.NewMessageFilter({pubKey: id})
	"e6b79234d9deba9f0d963e0367fd58f7e34a13dfe9b45c3876efb1dd19f9633a"

or

	> f = shh.NewMessageFilter({pubKey: '46af9c31a30c2eeb4e6fbb5d02a0b64b62d147e576f1503372a02d4f80ebb4e1'})
	"e6b79234d9deba9f0d963e0367fd58f7e34a13dfe9b45c3876efb1dd19f9633a"

Advertise your public key.
In this case: 
0x048d7938066b4fb9465879c837762a767648e9473e0a6a470d719f71024d4a59450b2151b303b5f90ea35fd2e8cd91968783da17add12973e9867c626750bae3e9

Regulary poll for the messages, using the saved subscription ID.

	> shh.getFilterMessages(f)

or

	> shh.getFilterMessages('e6b79234d9deba9f0d963e0367fd58f7e34a13dfe9b45c3876efb1dd19f9633a')

result:

	[{
		hash: "0x1426abdaefe906c10d2e94a8bdb85b6626cb5e9c3c94ff36667903811836e7a1",
		padding: "0x52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c64981855ad8681d0d86d1e91e00167939cb6694d2c422acd208a0072939487f6999eb9d18a44784045d87f3c67cf22746e995af5a25367951baa2ff6cd471c483f15fb90badb37c5821b6d95526a41a9504680b4e7c8b76",
		payload: "0x7777777777777777",
		pow: 4.4667393675027265,
		receipientPublicKey: "0x048d7938066b4fb9465879c837762a767648e9473e0a6a470d719f71024d4a59450b2151b303b5f90ea35fd2e8cd91968783da17add12973e9867c626750bae3e9",
		sig: "",
		timestamp: 1492885562,
		topic: "0x00000000",
		ttl: 7
	}]

#### Send (asymmetric encryption)

	> shh.post({ttl: 7, powTarget: 2.5 powTime: 2, payload: '0x7777777777777777', pubKey: '0x048d7938066b4fb9465879c837762a767648e9473e0a6a470d719f71024d4a59450b2151b303b5f90ea35fd2e8cd91968783da17add12973e9867c626750bae3e9'})

In this message neither Topic nor Signature is set. Payload is equivalent to an ASCII string "wwwwwwww".

#### Receive Symmetrically Encrypted Messages

In order to engage in symmetrically encrypted communication, both the parties must share the same symmetric key. In this example we assume that the parties have already exchanged the password and the Topic via a secure communication channel.

Derive symmetric key from the password, and save its ID.

	> id = shh.generateSymKeyFromPassword('test')
	"de6bc568f8601fac6ff2085d17c02754348ddbf4122ab1bd543a40c68d3a45fe"

Subcribe to messages, encrypted with this symmetric key.

	> f = shh.subscribe({topics: ['0x07678231'], symKeyID: id})
	"07b3ab8986aa321046010f093c8ab2ba4bd441e8435f58c7c75d5398e96faf42"

or 

	> f = shh.subscribe({topics: ['0x07678231'], symKeyID: 'de6bc568f8601fac6ff2085d17c02754348ddbf4122ab1bd543a40c68d3a45fe'})
	"07b3ab8986aa321046010f093c8ab2ba4bd441e8435f58c7c75d5398e96faf42"

Regulary poll for the messages, using the saved subscription ID.

	> shh.getFilterMessages(f)

or

	> shh.getFilterMessages('07b3ab8986aa321046010f093c8ab2ba4bd441e8435f58c7c75d5398e96faf42')

result:

	[{
		hash: "0x300b946c074e2b408b461ad685efba3686dcee90d37cdb45f975c91b2ee23489",
		padding: "0xcbe0255aa5b7d44bec40f84c892b9bffd43629b0223beea5f4f74391f445d15afd4294040374f6924b98cbf8713f8d962d7c8d019192c24224e2cafccae3a61fb586b14323a6bc8f9e7df1d929333ff993933bea6f5b3af6de0374366c4719e43a1b067d89bc7f01f1f573981659a44ff17a4c7215a3b539eb",
		payload: "0x68656c6c6f",
		pow: 6.19198790627362,
		receipientPublicKey: "",
		sig: "0x048d7938066b4fb9465879c837762a767648e9473e0a6a470d719f71024d4a59450b2151b303b5f90ea35fd2e8cd91968783da17add12973e9867c626750bae3e9",
		timestamp: 1492888296,
		topic: "0x07678231",
		ttl: 7
	}]

#### Send (symmetric encryption)

	> shh.post({ttl: 7, topic: '0x07678231', powTarget: 2.01, powTime: 2, payload: '0x68656c6c6f', symKeyID: id})

or

	> shh.post({ttl: 7, topic: '0x07678231', powTarget: 2.01, powTime: 2, payload: '0x68656c6c6f', symKeyID: 'de6bc568f8601fac6ff2085d17c02754348ddbf4122ab1bd543a40c68d3a45fe'})
	
If you want to sign messages you should first generate the signing key (same as asymmetric key)

	> s = shh.newKeyPair()
	"46af9c31a30c2eeb4e6fbb5d02a0b64b62d147e576f1503372a02d4f80ebb4e1"
	
and then add another parameter to the post 

	> shh.post({sig: s, ttl: 7, topic: '0x07678231', powTarget: 2.01, powTime: 2, payload: '0x68656c6c6f', symKeyID: id})

#### Engage in a Chat with One-Time Session Key (for plausible deniability)

Generate symmetric key, and save its ID.

	> id = shh.newSymKey()
	"ee3ece1e35c0d3e5bd2e878dd66bf0c25b7e10df3d6b092591adca69189a6c32"

Retrieve the newly created symmetric key.

	> shh.getSymKey(id)
	"3f4e735996b400637b3530d41d8bf8e0cbeafaf299aa0ad408c579569fd0af8c"

Send the raw key and Topic to you peer via a secure communication channel.
The peer should install the raw key:

	> id = shh.addSymKey('0x3f4e735996b400637b3530d41d8bf8e0cbeafaf299aa0ad408c579569fd0af8c')
	"be14387971d31c6a2997dac5062978294f52a145e5a0a0a2caa4b37dbec9bb13"

Both peers (or even multiple participants) subscribe to messages, encrypted with certain key and topic.

	> f = shh.newMessageFilter({type: topics: ['0x07678231'],  symKeyID: id})
	"e6b79234d9deba9f0d963e0367fd58f7e34a13dfe9b45c3876efb1dd19f9633a"

Regulary poll for the messages, using the saved subscription ID.

	> shh.getFilterMessages(f)
