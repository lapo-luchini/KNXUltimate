const knx = require("./index.js");
const KNXsecureKeyring = require("./src/KNXsecureKeyring.js");
// const KNXSecureSessionRequest = require('./src/protocol/KNXSecureSessionRequest');
// const KNXSecureSessionResponse = require("./src/protocol/KNXSecureSessionResponse").KNXSecureSessionResponse;
const KNXProtocol = require('./src/protocol/KNXProtocol').KNXProtocol;
const Curve25519 = require('./src/Curve25519');


let rawjKNXSecureKeyring = `<?xml version="1.0" encoding="utf-8"?>
<Keyring Project="KNX Secure" CreatedBy="6.0.5" Created="2022-09-11T09:01:28" Signature="eQl8q8x2W+k00K9t6+RhIw==" xmlns="http://knx.org/xml/keyring/1">
  <Backbone MulticastAddress="224.0.23.12" Latency="2000" Key="qKvBfLAKIPN8G6n2uV797w==" />
  <Interface IndividualAddress="3.1.2" Type="Tunneling" Host="3.1.1" UserID="2" Password="kyvut6HSZ6oOakBBklvqNGcPmp002TWpJPB8lTrr1jM=" Authentication="X+i4qknThJEUB0+2UBF7FI06IYe67FfazV9vfPiMc68=" />
  <Interface IndividualAddress="3.1.3" Type="Tunneling" Host="3.1.1" UserID="3" Password="Nw5zOfprxYtD+FQu861m0MTFGNOcFLXUisJCjWFwCDs=" Authentication="RIA1Geyo3r++6EDCKK5pwWv83UJZjTGiG/B6t7ez47M=" />
  <Interface IndividualAddress="3.1.4" Type="Tunneling" Host="3.1.1" UserID="4" Password="dfFkoklhK/KAA17XZTdGFEa5t5UxLxcPtJxttiesCfc=" Authentication="Z7+H91/+D+5DEYVVgOZlj2UspMuzLcN+rOmwIcnyEqs=" />
  <Interface IndividualAddress="3.1.5" Type="Tunneling" Host="3.1.1" UserID="5" Password="4JHOOT8QzO92g2JDrvCWOP5+aQG4lzfVX67HwcfSLhI=" Authentication="RHx9QnaqKbH6ku30eSWTyI9IwiBJeLrruasOvoDYMKU=" />
  <Interface IndividualAddress="3.1.6" Type="Tunneling" Host="3.1.1" UserID="6" Password="LuBWxeIAG9JN0AXbCXwzne5+HNqJYnb72PhYsAT1xHI=" Authentication="XTRtzA5/v4kCdiYo6+++UdSkxqChwAqZg0UEh2pASK8=" />
  <Interface IndividualAddress="3.1.7" Type="Tunneling" Host="3.1.1" UserID="7" Password="XkHWhGzkR0w2691UuYQt84TxILji7YLYxdVLTcw72LM=" Authentication="XOiuJkeUZWHdNzqEIDwqgOJCijlS20VkzBiTbaNY7Z8=" />
  <Interface IndividualAddress="3.1.8" Type="Tunneling" Host="3.1.1" UserID="8" Password="g2h2u9UdfEryuI0PdwoQNWDkqBsXqp6tYSG6JrtLYZQ=" Authentication="BlEG79s+fg9Q7g8MPlrkbZVwLnnJXeX3p9o7za6EofM=" />
  <Interface IndividualAddress="3.1.9" Type="Tunneling" Host="3.1.1" UserID="9" Password="W654HFS7BZlmh2BaS56lDDaRdrEOzh0J5VSo2w+DKBQ=" Authentication="Hm96LNTleilkbXJKyCZG4ivetKOjUkv59WFYhFAEwEs=" />
  <GroupAddresses>
    <Group Address="16384" Key="i/SPfza/PfYm0qzJYOU9hA==" />
    <Group Address="16385" Key="AneeYsqajqfVBSARDUdLRA==" />
    <Group Address="16386" Key="m2m651Mu2waJZkPAgS/idg==" />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="3.1.1" ToolKey="Bm2jy410EFHxgT7zin+hug==" ManagementPassword="ldhMMR5uDqBt8TcO0cutDzlVZeXb9WoPwd7LVTcATjk=" Authentication="fRdXfcjp1jlh/y/mxzhWTUTHQ7QgbkZzn9QF3zqv04Q=" SequenceNumber="121960556365" />
    <Device IndividualAddress="3.1.10" ToolKey="NNebol5t4c5ZmOI73B+s3w==" SequenceNumber="121960675346" />
    <Device IndividualAddress="3.1.11" ToolKey="jsS5Ior3UnnofoE1ZfNKjA==" SequenceNumber="121960725775" />
  </Devices>
</Keyring>`;

let knxUltimateClientProperties = {
    ipAddr: "192.168.1.54",
    ipPort: "3671",
    physAddr: "1.1.100",
    suppress_ack_ldatareq: false,
    loglevel: "debug", // or "debug" is the default
    localEchoInTunneling: true, // Leave true, forever.
    hostProtocol: "TunnelTCP", // "Multicast" in case you use a KNX/IP Router, "TunnelUDP" in case of KNX/IP Interface, "TunnelTCP" in case of secure KNX/IP Interface (not yet implemented)
    isSecureKNXEnabled: true, // Leave "false" until KNX-Secure has been released
    KNXEthInterface: "LAN", // Bind to the first avaiable local interfavce. "Manual" if you wish to specify the interface (for example eth1); in this case, set the property interface to the interface name (interface:"eth1")
    localIPAddress: "", // Leave blank, will be automatically filled by KNXUltimate
    jKNXSecureKeyring: "", // This is the unencrypted Keyring file content (see below)
};

async function go() {
    knxUltimateClientProperties.jKNXSecureKeyring = await KNXsecureKeyring.keyring.load(rawjKNXSecureKeyring, "banana");
    let knxUltimateClient = new knx.KNXClient(knxUltimateClientProperties);

    const priv = Buffer.from('b8fabd62665d8b9e8a9d8b1f4bca42c8c2789a6110f50e9dd785b3ede883f378','hex');
    const myKey = Curve25519.generateKeyPair(priv);
    const data = Buffer.from('0610095200380001bdf099909923143ef0a5de0b3be3687bc5bd3cf5f9e6f901699cd870ec1ff824a922505aaa436163570bd5494c2df2a3', 'hex');
    
    knxUltimateClientProperties.jKNXSecureKeyring.tunnel = {
        dhSecret: myKey
    };

    console.log('My public    ', Buffer.from(myKey.public).toString('hex'));
    console.log('Device public bdf099909923143ef0a5de0b3be3687bc5bd3cf5f9e6f901699cd870ec1ff824 (expected)');

    // KNXSecureSessionResponse.createFromBuffer(data);
    KNXProtocol.parseMessage(data);
}

go();
