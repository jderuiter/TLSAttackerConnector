import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutorFactory;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;

public class TLSAttackerConnector {
	TlsConfig config;
	TlsContext context;
	ActionExecutor executor;
	
	public TLSAttackerConnector() throws IOException {
		// Add BouncyCastle, otherwise encryption will be invalid and it's not possible to perform a valid handshake
		Security.addProvider(new BouncyCastleProvider());
		
		config = TlsConfig.createConfig();
		config.setHost("localhost:4433");
		config.setHighestProtocolVersion(ProtocolVersion.TLS12);
		// Timeout that is used when waiting for incoming messages
		config.setTlsTimeout(200);

		initialise();
	}
	
	public void reset() throws IOException {
		close();
		initialise();
	}
	
	public void close() {
		context.getTransportHandler().closeConnection();
	}	
	
	public void initialise() throws IOException {
		context = new TlsContext(config);
		
		// Set initial configuration to support out of order messages
		context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
		context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
		context.setHighestClientProtocolVersion(ProtocolVersion.TLS12);
		
		List<CipherSuite> cipherSuites = new LinkedList<>();
		cipherSuites.add(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
		context.setClientSupportedCiphersuites(cipherSuites);
		
		TransportHandler th = TransportHandlerFactory.createTransportHandler("localhost", 4433, context.getConfig()
                .getConnectionEnd(), context.getConfig().getTlsTimeout(), context.getConfig().getTimeout(), context
                .getConfig().getTransportHandlerType());
		th.initialize();
		
		context.setTransportHandler(th);
        context.setRecordLayer(RecordLayerFactory.getRecordLayer(context.getConfig().getRecordLayerType(), context));
        
        executor = ActionExecutorFactory.getActionExecutor(context.getConfig().getExecutorType(), context);		
	}
	
	public void sendMessage(ProtocolMessage message) {
		List<ProtocolMessage> messages = new LinkedList<>();
		messages.add(message);
		new SendAction(messages).execute(context, executor);
		
		if(message.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
			context.getRecordLayer().updateEncryptionCipher();
		}
	}
    
	public String receiveMessages() throws IOException {
		List<String> receivedMessages = new LinkedList<>();
		ReceiveAction action = new ReceiveAction(new LinkedList<ProtocolMessage>());
		
		// Perform the actual receiving of the message
		action.execute(context, executor);
		
		String outputMessage;
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
	
	public String processInput(String inputSymbol) throws IOException {
		switch(inputSymbol) {
		case "RESET":
			reset();
			return "";
			
		case "ClientHello":
			sendMessage(new ClientHelloMessage());
			break;
			
		case "ServerHello":
			sendMessage(new ServerHelloMessage());
			break;			
			
		case "RSAClientKeyExchange":
			sendMessage(new RSAClientKeyExchangeMessage());
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
		}
		
		return receiveMessages();
	}
	
	public void startListening(int port) throws IOException {
		ServerSocket serverSocket = new ServerSocket(port);
	    Socket clientSocket = serverSocket.accept();
		
	    PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
	    BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

	    String input, output;
	    
	    while((input = in.readLine()) != null) {
	    	System.out.println("Received input: " + input);
	        output = processInput(input);
	        System.out.println("Responding with output: " + output);
	        out.println(output);
	    }	    
	    
	    clientSocket.close();
	    serverSocket.close();
	}
	
	public static void main(String[] args) throws IOException{
		/*		 
		Security.addProvider(new BouncyCastleProvider());

		TlsConfig config = TlsConfig.createConfig();
		config.setHost("localhost:4433");
		config.setHighestProtocolVersion(ProtocolVersion.TLS12);

		WorkflowTrace trace = new WorkflowTrace();
		
		trace.add(new SendAction(new ClientHelloMessage()));
		
		List<ProtocolMessage> messages = new LinkedList<ProtocolMessage>();
		messages.add(new ServerHelloMessage());
		messages.add(new CertificateMessage());
		messages.add(new ServerHelloDoneMessage());		
		trace.add(new ReceiveAction(messages));
		
		messages.clear();
		messages.add(new RSAClientKeyExchangeMessage());
		messages.add(new ChangeCipherSpecMessage());		
		messages.add(new FinishedMessage());				
		trace.add(new SendAction(messages));
		trace.add(new ReceiveAction(new ChangeCipherSpecMessage()));
		trace.add(new ReceiveAction(new FinishedMessage()));

		ApplicationMessage ad = new ApplicationMessage();
		ModifiableByteArray data = new ModifiableByteArray();
		data.setModification(ByteArrayModificationFactory.explicitValue("GET / HTTP/1.0\n".getBytes())); 
		ad.setData(data);
		
		trace.add(new SendAction(ad));
		trace.add(new ReceiveAction(new ApplicationMessage()));
		
		config.setWorkflowTrace(trace);
		TlsContext context = new TlsContext(config);
*/				
//		DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(context);		
//		executor.executeWorkflow();

        //context.getTransportHandler().closeConnection();		

		TLSAttackerConnector connector = new TLSAttackerConnector();
		connector.startListening(4444);
		/*
		System.out.println("ClientHello: " + connector.processInput("ClientHello"));
		System.out.println("RSAClientKeyExchange: " + connector.processInput("RSAClientKeyExchange"));
		System.out.println("ChangeCipherSpec: " + connector.processInput("ChangeCipherSpec"));
		System.out.println("Finished: " + connector.processInput("Finished"));
		System.out.println("ApplicationData: " + connector.processInput("ApplicationData"));
		*/
	}
}
