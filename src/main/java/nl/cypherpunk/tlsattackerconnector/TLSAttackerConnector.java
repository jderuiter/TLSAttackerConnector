package nl.cypherpunk.tlsattackerconnector;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.rub.nds.modifiablevariable.bytearray.*;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutorFactory;
import de.rub.nds.tlsattacker.transport.SimpleTransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 *
 */
public class TLSAttackerConnector {
	TlsConfig config;
	TlsContext context;
	ActionExecutor executor;
	
	String targetHostname = "localhost";
	int targetPort = 4433;
	
	/**
	 * Intialise the TLS-Attacker connector
	 * 
	 * @throws IOException
	 */
	public TLSAttackerConnector() throws IOException {
		// Add BouncyCastle, otherwise encryption will be invalid and it's not possible to perform a valid handshake
		Security.addProvider(new BouncyCastleProvider());
		
		// Disable logging
		LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
		Configuration ctxConfig = loggerContext.getConfiguration();
		LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
		loggerConfig.setLevel(Level.OFF); 
		
		config = TlsConfig.createConfig();
		//config.setHost("localhost:4433");
		config.setHighestProtocolVersion(ProtocolVersion.TLS12);
		// Timeout that is used when waiting for incoming messages
		config.setTimeout(100);

		initialise();
	}
	
	/**
	 * Reset the connection with the TLS implementation by closing the current socket and initialising a new session
	 * 
	 * @throws IOException
	 */
	public void reset() throws IOException {
		close();
		initialise();
	}
	
	/**
	 * Close the current connection
	 */
	public void close() {
		context.getTransportHandler().closeConnection();
	}	
	
	/**
	 * Initialise a TLS connection by configuring a new context and connecting to the server 
	 * 
	 * @throws IOException
	 */
	public void initialise() throws IOException {
		context = new TlsContext(config);
		
		// Set initial configuration to support out of order messages
		context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
		//context.setSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
		context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
		context.setHighestClientProtocolVersion(ProtocolVersion.TLS12);
		
		// Create the list of supported cipher suites
		List<CipherSuite> cipherSuites = new LinkedList<>();
		cipherSuites.add(context.getSelectedCipherSuite());
		context.setClientSupportedCiphersuites(cipherSuites);
		
		// Set supported compression algorithms
		List<CompressionMethod> compressionMethods = new LinkedList<>();	
		compressionMethods.add(CompressionMethod.NULL);
		context.setClientSupportedCompressions(compressionMethods);

		// Create the transport handler that takes care of the actual network communication with the TLS implementation
		ConnectorTransportHandler transporthandler = new ConnectorTransportHandler(targetHostname, targetPort, context.getConfig().getConnectionEnd(), context.getConfig().getTimeout());
		transporthandler.initialize();

		context.setTransportHandler(transporthandler);
        context.setRecordLayer(RecordLayerFactory.getRecordLayer(context.getConfig().getRecordLayerType(), context));
        
        executor = ActionExecutorFactory.getActionExecutor(context.getConfig().getExecutorType(), context);		
	}
	
	/**
	 * Send the provided message to the TLS implementation
	 * 
	 * @param message Message to be sent
	 */
	protected void sendMessage(ProtocolMessage message) {
		List<ProtocolMessage> messages = new LinkedList<>();
		messages.add(message);
		new SendAction(messages).execute(context, executor);
		
		// If we send an CCS message, enable encryption and/or update the keys
		if(message.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
			context.getRecordLayer().updateEncryptionCipher();
		}
	}
    
	/**
	 * Receive message on the TLS connection
	 * 
	 * @return A string representation of the message types that were received
	 * @throws IOException
	 */
	protected String receiveMessages() throws IOException {
		// First check if the socket is still open
		if(((ConnectorTransportHandler)context.getTransportHandler()).isSocketClosed()) {
			return "ConnectionClosed";
		}
		
		List<String> receivedMessages = new LinkedList<>();
		ReceiveAction action = new ReceiveAction(new LinkedList<ProtocolMessage>());
		
		// Perform the actual receiving of the message
		action.execute(context, executor);
		
		String outputMessage;
		
		// Iterate over all received messages and build a string containing their respective types
		for(ProtocolMessage message: action.getActualMessages()) {
			if(message.getProtocolMessageType() == ProtocolMessageType.ALERT) {
				AlertMessage alert = (AlertMessage)message;
				outputMessage = "ALERT_" + AlertLevel.getAlertLevel(alert.getLevel().getValue()).name() + "_" + AlertDescription.getName(alert.getDescription().getValue());
			}
			else {
				outputMessage = message.toCompactString();
			}
			receivedMessages.add(outputMessage);
		}
		
		if(receivedMessages.size() > 0) {
			return String.join("|", receivedMessages);
		} else {
			return "-";
		}
	}
	
	/**
	 * Send a message of the provided type and return the types of the response messages
	 * 
	 * @param inputSymbol A string indicating which type of message to send
	 * @return A string representation of the message types that were received
	 * @throws Exception 
	 */
	public String processInput(String inputSymbol) throws Exception {
		// Upon receiving the special input symbol RESET, we reset the system
		if(inputSymbol.equals("RESET")) {
			reset();
			return "";			
		}
		
		// Check if the socket is already closed, in which case we don't have to bother trying to send data out
		if(((ConnectorTransportHandler)context.getTransportHandler()).isSocketClosed()) {
			return "ConnectionClosed";
		}

		// Process the regular input symbols
		switch(inputSymbol) {
		case "ClientHello":
			ClientHelloMessage clientHello = new ClientHelloMessage();
			ModifiableByteArray cipherSuites = new ModifiableByteArray();
			cipherSuites.setModification(ByteArrayModificationFactory.explicitValue(context.getSelectedCipherSuite().getByteValue()));
			clientHello.setCipherSuites(cipherSuites);
			sendMessage(clientHello);
			break;
			
		case "ServerHello":
			sendMessage(new ServerHelloMessage());
			break;			
			
		case "Certificate":
			sendMessage(new CertificateMessage());
			break;
			
		case "CertificateRequest":
			sendMessage(new CertificateRequestMessage());
			break;
			
		case "DHEServerKeyExchange":
			sendMessage(new DHEServerKeyExchangeMessage());
			break;
			
		case "ServerHelloDone":
			sendMessage(new ServerHelloDoneMessage());
			break;
		
		case "RSAClientKeyExchange":
			sendMessage(new RSAClientKeyExchangeMessage());
			break;

		case "DHClientKeyExchange":
			//TODO Supply DH PublicKey in case none is provided by the server
			sendMessage(new DHClientKeyExchangeMessage());
			break;
			
		case "ChangeCipherSpec":
			sendMessage(new ChangeCipherSpecMessage());
			break;
			
		case "Finished":
			sendMessage(new FinishedMessage());
			break;
			
		case "ApplicationData":
			ApplicationMessage ad = new ApplicationMessage();
			ModifiableByteArray data = new ModifiableByteArray();
			data.setModification(ByteArrayModificationFactory.explicitValue("GET / HTTP/1.0\n".getBytes()));
			ad.setData(data);
			
			sendMessage(ad);
			break;
		
		default:
			throw new Exception("Unknown input symbol");
		}
		
		return receiveMessages();
	}
	
	/**
	 * Start listening on the provided to port for a connection to provide input symbols and return output symbols. Only one connection is accepted at the moment.
	 * 
	 * @param port The port to listen on
	 * @throws Exception 
	 */
	public void startListening(int port) throws Exception {
		ServerSocket serverSocket = new ServerSocket(port);
		System.out.println("Listening on port " + port);
		
	    Socket clientSocket = serverSocket.accept();
	    clientSocket.setTcpNoDelay(true);
		
	    PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
	    BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

	    String input, output;
	    
	    while((input = in.readLine()) != null) {
	        output = processInput(input);
	        System.out.println(input + " / " + output);
	        out.println(output);
	        out.flush();
	    }	    
	    
	    clientSocket.close();
	    serverSocket.close();
	}
	
	public static void main(String[] args) {
		try {
			TLSAttackerConnector connector = new TLSAttackerConnector();
			connector.startListening(4444);
			
			//System.out.println("ServerHello: " + connector.processInput("ServerHello"));
			//System.out.println("Certificate: " + connector.processInput("Certificate"));
			//System.out.println("CertificateRequest: " + connector.processInput("CertificateRequest"));
			//System.out.println("DHEServerKeyExchange: " + connector.processInput("DHEServerKeyExchange"));
			//System.out.println("ServerHelloDone: " + connector.processInput("ServerHelloDone"));
			
			/*
			System.out.println("ClientHello: " + connector.processInput("ClientHello"));
			System.out.println("RSAClientKeyExchange: " + connector.processInput("RSAClientKeyExchange"));
			//System.out.println("DHClientKeyExchange: " + connector.processInput("DHClientKeyExchange"));
			System.out.println("ChangeCipherSpec: " + connector.processInput("ChangeCipherSpec"));
			System.out.println("Finished: " + connector.processInput("Finished"));
			System.out.println("ApplicationData: " + connector.processInput("ApplicationData"));
*/
		} catch(Exception e) {
			System.err.println("Error occured: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}
