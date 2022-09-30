
const knx = require("./index.js");
const KNXsecureKeyring = require("./src/KNXsecureKeyring.js");
const dptlib = require('./src/dptlib');

// const realLog = console.log;
// console.log = (s) => {
//     realLog(s);
// };

// This is the content of the ETS Keyring file obtained doing this: https://www.youtube.com/watch?v=OpR7ZQTlMRU
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

// Set the properties
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

async function LoadKeyringFile(_keyring, _password) {
    return KNXsecureKeyring.keyring.load(_keyring, _password);
}

async function go() {

    // Load the Keyring, decrypt it and put it in the jKNXSecureKeyring property.
    // The password "banana" has been used to encrypt the keyring file during export form ETS.
    // Again, see this https://www.youtube.com/watch?v=OpR7ZQTlMRU
    knxUltimateClientProperties.jKNXSecureKeyring = await LoadKeyringFile(rawjKNXSecureKeyring, "banana");


    // Log some infos
    console.log("KNX-Secure: Keyring for ETS proj " + knxUltimateClientProperties.jKNXSecureKeyring.ETSProjectName + ", created by " + knxUltimateClientProperties.jKNXSecureKeyring.ETSCreatedBy + " on " + knxUltimateClientProperties.jKNXSecureKeyring.ETSCreated + " succesfully validated with provided password");

    // Instantiate the client
    var knxUltimateClient = new knx.KNXClient(knxUltimateClientProperties);

    // This contains the decrypted keyring file, accessible to all .js files referencing the "index.js" module.
    console.log(knx.getDecodedKeyring());

    // Setting handlers
    // ######################################
    knxUltimateClient.on(knx.KNXClient.KNXClientEvents.indication, handleBusEvents);
    knxUltimateClient.on(knx.KNXClient.KNXClientEvents.error, err => {
        // Error event
        console.log("Error", err)
    });
    knxUltimateClient.on(knx.KNXClient.KNXClientEvents.ackReceived, (knxMessage, info) => {
        // In -->tunneling mode<-- (in ROUTING mode there is no ACK event), signals wether the last KNX telegram has been acknowledge or not
        // knxMessage: contains the telegram sent.
        // info is true it the last telegram has been acknowledge, otherwise false.
        console.log("Last telegram acknowledge", knxMessage, info)
    });
    knxUltimateClient.on(knx.KNXClient.KNXClientEvents.disconnected, info => {
        // The client is cisconnected
        console.log("Disconnected", info)
    });
    knxUltimateClient.on(knx.KNXClient.KNXClientEvents.close, info => {
        // The client physical net socket has been closed
        console.log("Closed", info)
    });
    knxUltimateClient.on(knx.KNXClient.KNXClientEvents.connected, info => {
        // The client is connected
        console.log("Connected. On Duty", info)
        // Write something to the BUS
        if (knxUltimateClient._getClearToSend()) knxUltimateClient.write("0/1/1", false, "1.001");
    });
    knxUltimateClient.on(knx.KNXClient.KNXClientEvents.connecting, info => {
        // The client is setting up the connection
        console.log("Connecting...", info)
    });
    // ######################################

    // Handle BUS events
    // ---------------------------------------------------------------------------------------
    function handleBusEvents(_datagram, _echoed) {

        // This function is called whenever a KNX telegram arrives from BUS

        // Get the event
        let _evt = "";
        let dpt = "";
        let jsValue;
        if (_datagram.cEMIMessage.npdu.isGroupRead) _evt = "GroupValue_Read";
        if (_datagram.cEMIMessage.npdu.isGroupResponse) _evt = "GroupValue_Response";
        if (_datagram.cEMIMessage.npdu.isGroupWrite) _evt = "GroupValue_Write";
        // Get the source Address
        let _src = _datagram.cEMIMessage.srcAddress.toString();
        // Get the destination GA
        let _dst = _datagram.cEMIMessage.dstAddress.toString()
        // Get the RAW Value
        let _Rawvalue = _datagram.cEMIMessage.npdu.dataValue;

        // Decode the telegram. 
        if (_dst === "0/1/1") {
            // We know that 0/1/1 is a boolean DPT 1.001
            dpt = dptlib.resolve("1.001");
            jsValue = dptlib.fromBuffer(_Rawvalue, dpt)
        } else if (_dst === "0/1/2") {
            // We know that 0/1/2 is a boolean DPT 232.600 Color RGB
            dpt = dptlib.resolve("232.600");
            jsValue = dptlib.fromBuffer(_Rawvalue, dpt)
        } else {
            // All others... assume they are boolean
            dpt = dptlib.resolve("1.001");
            jsValue = dptlib.fromBuffer(_Rawvalue, dpt)
            if (jsValue === null) {
                // Is null, try if it's a numerical value
                dpt = dptlib.resolve("5.001");
                jsValue = dptlib.fromBuffer(_Rawvalue, dpt)
            }
        }
        console.log("src: " + _src + " dest: " + _dst, " event: " + _evt, " value: " + jsValue);


    }

    knxUltimateClient.Connect();

    // Wait some seconds, just for fun
    await new Promise((resolve, reject) => setTimeout(resolve, 10000));

    // Disconnects
    if (knxUltimateClient.isConnected()) knxUltimateClient.Disconnect();

}

go();