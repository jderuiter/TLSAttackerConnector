package nl.cypherpunk.tlsattackerconnector;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.JAXBException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 *
 */
public class TLSAttackerConnector {
	static String SYMBOL_CONNECTION_CLOSED = "ConnectionClosed";
	static String SYMBOL_RESET = "RESET";
	
	Config config;
	State state;
	HashMap<String, WorkflowTrace> messages = new HashMap<>();

	@Parameter(names = {"--listen", "-l"}, description = "Listen port")
	int listenPort = 6666;	
	@Parameter(names = {"--targetHost", "-tH"}, description = "Target host")
	String targetHostname = "localhost";
	@Parameter(names = {"--targetPort", "-tP"}, description = "Target port")
	int targetPort = 4433;
	@Parameter(names = {"--timeout", "-t"}, description = "Timeout")
	int timeout = 100;
	
	@Parameter(names = {"--cipherSuite", "-cS"}, description = "Comma-separated list of ciphersuites to use. If none is provided this will default to TLS_RSA_WITH_AES_128_CBC_SHA256.")
	List<String> cipherSuiteStrings = new ArrayList<>();
	
	@Parameter(names = {"--protocolVersion", "-pV"}, description = "TLS version to use")
	String protocolVersionString = "TLS12";
	@Parameter(names = {"--compressionMethod", "-cM"}, description = "CompressionMethod to use")
	String compressionMethodString = "NULL";
	
	@Parameter(names = {"--messageDir", "-mD"}, description = "Directory to load messages from")
	String messageDir = "messages";
	
	@Parameter(names = {"--help", "-h"}, description = "Display help", help = true)
	private boolean help;
	@Parameter(names = {"--test"}, description = "Run test handshake")
	private boolean test;
	@Parameter(names = {"--testCipherSuites"}, description = "Try to determine which CipherSuites are supported")
	private boolean testCipherSuites;
	@Parameter(names = {"--listMessages"}, description = "List all loaded messages")
	private boolean listMessages;	
	
	/**
	 * Create the TLS-Attacker connector
	 * 
	 */
	public TLSAttackerConnector() {
		// Add BouncyCastle, otherwise encryption will be invalid and it's not possible to perform a valid handshake
		Security.addProvider(new BouncyCastleProvider());
		UnlimitedStrengthEnabler.enable();
		
		// Disable logging
		Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.OFF);
	}
	
	/**
	 * Intialise the TLS-Attacker connector
	 * 
	 * @throws Exception
	 */	
	public void initialise() throws Exception {
		// Configure TLS-Attacker
		config = Config.createConfig();
		config.setEnforceSettings(false);
		
		// Configure hosts
		OutboundConnection clientConnection = new OutboundConnection(targetPort,  targetHostname);
		// Timeout that is used when waiting for incoming messages
		clientConnection.setTimeout(timeout);
		config.setDefaultClientConnection(clientConnection);
				
		// Parse provided CipherSuite		
		List<CipherSuite> cipherSuites = new LinkedList<>();
		for(String cipherSuiteString: cipherSuiteStrings) {
			try {
				cipherSuites.add(CipherSuite.valueOf(cipherSuiteString));
			}
			catch(java.lang.IllegalArgumentException e) {
				throw new Exception("Unknown CipherSuite " + cipherSuiteString);
			}	
		}
		// If no CipherSuites are provided, set the default
		if(cipherSuites.size() == 0) {
			cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
		}
	
		// Parse CompressionMethod
		CompressionMethod compressionMethod;
		try {
			compressionMethod = CompressionMethod.valueOf(compressionMethodString);
		}
		catch(java.lang.IllegalArgumentException e) {
			throw new Exception("Unknown CompressionMethod " + compressionMethodString); 
		}				
		
		// TLS specific settings
		
		// Set TLS version
		ProtocolVersion protocolVersion = ProtocolVersion.fromString(protocolVersionString);
		config.setHighestProtocolVersion(protocolVersion);
		config.setDefaultSelectedProtocolVersion(protocolVersion);
		config.setDefaultHighestClientProtocolVersion(protocolVersion);
		
		// Set default selected CipherSuite. This will be the first in the list of specified CipherSuites, which will always contain at least one element
		config.setDefaultSelectedCipherSuite(cipherSuites.get(0));
		
		// Set the list of supported cipher suites
		config.setDefaultClientSupportedCiphersuites(cipherSuites);
		
		// Set supported compression algorithms
		List<CompressionMethod> compressionMethods = new LinkedList<>();	
		compressionMethods.add(compressionMethod);
		config.setDefaultClientSupportedCompressionMethods(compressionMethods);
		
		// Set default DH parameters
		config.setDefaultClientDhGenerator(new BigInteger("2"));
		config.setDefaultClientDhModulus(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
		config.setDefaultClientDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
		config.setDefaultClientDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
		config.setDefaultServerDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
		config.setDefaultServerDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
		
		config.setAddRenegotiationInfoExtension(true);
		
		initialiseSession();		
	}

	/**
	 * Reset the connection with the TLS implementation by closing the current socket and initialising a new session
	 * 
	 * @throws IOException
	 */
	public void reset() throws IOException {
		close();
		initialiseSession();
	}
	
	/**
	 * Close the current connection
	 * @throws IOException 
	 */
	public void close() throws IOException {
		state.getTlsContext().getTransportHandler().closeConnection();
	}	
	
	/**
	 * Initialise a TLS connection by configuring a new context and connecting to the server
	 * 
	 * @throws IOException
	 */
	public void initialiseSession() throws IOException {
		state = new State(config);

		TlsContext context = state.getTlsContext();

		//TransportHandler transporthandler = TransportHandlerFactory.createTransportHandler(config.getConnectionEnd());
		ConnectorTransportHandler transporthandler = new ConnectorTransportHandler(config.getDefaultClientConnection().getTimeout(), config.getDefaultClientConnection().getHostname(), config.getDefaultClientConnection().getPort());
		context.setTransportHandler(transporthandler);
		
		context.initTransportHandler();
        context.initRecordLayer();
	}
	
	/**
	 * Send the provided message to the TLS implementation
	 * 
	 * @param message ProtocolMessage to be sent
	 */
	protected void sendMessage(ProtocolMessage message) {
		List<ProtocolMessage> messages = new LinkedList<>();
		messages.add(message);

		SendAction action = new SendAction(messages);
		
		WorkflowTrace test = new WorkflowTrace();
		test.addTlsAction(action);
		try {
			System.out.println(WorkflowTraceSerializer.write(test));
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Need to normalize otherwise an exception is thrown about no connection existing with alias 'null'
		action.normalize();
		action.execute(state);
	}
	
	/**
	 * Execute the provided trace
	 * 
	 * @param trace WorkflowTrace to be executed
	 */
	protected void sendMessage(WorkflowTrace trace) {
		for(TlsAction tlsAction: trace.getTlsActions()) {
			try {
				tlsAction.normalize();
				tlsAction.execute(state);
			} catch (WorkflowExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// Reset trace so we can execute it again
		trace.reset();
	}	
    
	/**
	 * Receive message on the TLS connection
	 * 
	 * @return A string representation of the message types that were received
	 * @throws IOException
	 */
	protected String receiveMessages() throws IOException {
		// First check if the socket is still open
		if(state.getTlsContext().getTransportHandler().isClosed()) {
			return SYMBOL_CONNECTION_CLOSED;
		}
		
		List<String> receivedMessages = new LinkedList<>();
		ReceiveAction action = new ReceiveAction(new LinkedList<ProtocolMessage>());
		// Need to normalize otherwise an exception is thrown about no connection existing with alias 'null'		
		action.normalize();
		// Perform the actual receiving of the message
		action.execute(state);
		
		String outputMessage;
		
		// Iterate over all received messages and build a string containing their respective types
		for(ProtocolMessage message: action.getReceivedMessages()) {
			if(message.getProtocolMessageType() == ProtocolMessageType.ALERT) {
				AlertMessage alert = (AlertMessage)message;		
				AlertLevel level = AlertLevel.getAlertLevel(alert.getLevel().getValue());
				AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
				outputMessage = "ALERT_" + level.name() + "_";
				if(description == null) {
					outputMessage += "UNKNOWN";
				} else {	
					outputMessage += description.name();
				}
			}
			else {
				outputMessage = message.toCompactString();
			}
			receivedMessages.add(outputMessage);
		}
		
		if(state.getTlsContext().getTransportHandler().isClosed()) {
			receivedMessages.add(SYMBOL_CONNECTION_CLOSED);
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
		if(inputSymbol.equals(SYMBOL_RESET)) {
			reset();
			return "";			
		}
		
		// Check if the socket is already closed, in which case we don't have to bother trying to send data out
		if(state.getTlsContext().getTransportHandler().isClosed()) {
			return SYMBOL_CONNECTION_CLOSED;
		}

		// Process the regular input symbols
		if(messages.containsKey(inputSymbol)) {
			sendMessage(messages.get(inputSymbol));
		} else {
			throw new Exception("Unknown input symbol: " + inputSymbol);
		}
		
		return receiveMessages();
	}
	
	/**
	 * Start listening on the provided to port for a connection to provide input symbols and return output symbols. Only one connection is accepted at the moment.
	 * 
	 * @throws Exception 
	 */
	public void startListening() throws Exception {
		ServerSocket serverSocket = new ServerSocket(listenPort);
		System.out.println("Listening on port " + listenPort);
		
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
	
	/**
	 * Load messages from the specified directory. Each message should be in a separate file with the xml extension and contain workflow trace in XML format.
	 * 
	 * @param dirPath Path to load files containing messages from
	 * @throws Exception
	 */
	public void loadMessages(String dirPath) throws Exception {
        File dir = new File(dirPath);
        
        if(!dir.isDirectory()) {
        	throw new Exception(dirPath + " is not a valid directory");
        }
        
        // Get a list of all *.xml files in the provided directory 
        File[] files = dir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.toLowerCase().endsWith(".xml");
            }
        });
        
        for(File file: files) {
        	// Strip .xml from the end to get the message name
        	String name = file.getName().substring(0, file.getName().length() - 4);
        	
        	// Read the workflow trace from the file
			FileInputStream input = new FileInputStream(file.getAbsolutePath());
			WorkflowTrace trace = WorkflowTraceSerializer.read(input);
			
        	messages.put(name, trace);
        }
	}
	
	/**
	 * @return A list of all loaded messages that can be used as input symbols
	 */
	public String[] listMessages() {
		String[] list = new String[messages.size()];
		int i = 0;
		for(String name: messages.keySet()) {
			list[i++] = name;
		}
		return list;
	}
	
	public static void main(String ... argv) {
		try {
			TLSAttackerConnector connector = new TLSAttackerConnector();
			
			// Parse commandline arguments
	        JCommander commander = JCommander.newBuilder()
	        .addObject(connector)
            .build();
            commander.parse(argv);			

            if (connector.help) {
                commander.usage();
                return;
            }
            
            // Initialise the connector after the arguments are set
            connector.initialise();
            
            connector.loadMessages(connector.messageDir);
            
            if(connector.listMessages) {
            	System.out.println("========================================");
            	System.out.println("Loaded messages:");
            	for(String msg: connector.listMessages()) {
            		System.out.println(msg);
            	}
            	System.out.println("========================================");
            }
            
            if(connector.test) {
    			System.out.println("ClientHello: " + connector.processInput("ClientHello"));

    			CipherSuite selectedCipherSuite = connector.state.getTlsContext().getSelectedCipherSuite();
    			if(selectedCipherSuite == null) {
    				System.out.println("RSAClientKeyExchange: " + connector.processInput("RSAClientKeyExchange"));
    			}
    			else if(selectedCipherSuite.name().contains("ECDH")) {
        			System.out.println("ECDHClientKeyExchange: " + connector.processInput("ECDHClientKeyExchange"));    				
    			} else if(selectedCipherSuite.name().contains("DH")) {
        			System.out.println("DHClientKeyExchange: " + connector.processInput("DHClientKeyExchange"));
    			} else if(selectedCipherSuite.name().contains("RSA")) {
    				System.out.println("RSAClientKeyExchange: " + connector.processInput("RSAClientKeyExchange"));    				
    			}
    			
    			System.out.println("ChangeCipherSpec: " + connector.processInput("ChangeCipherSpec"));
    			System.out.println("Finished: " + connector.processInput("Finished"));
    			System.out.println("ApplicationData: " + connector.processInput("ApplicationData"));
    			System.out.println("AlertWarningCloseNotify: " + connector.processInput("AlertWarningCloseNotify"));
            }
            else if(connector.testCipherSuites) {
                for(CipherSuite cs: CipherSuite.values()) {
                	List<CipherSuite> cipherSuites = new ArrayList<>();
                	cipherSuites.add(cs);
            		connector.config.setDefaultSelectedCipherSuite(cs);
            		connector.config.setDefaultClientSupportedCiphersuites(cipherSuites);            		
            		
                	try {
                    	connector.processInput("RESET");                		
                		System.out.println(cs.name() + " " + connector.processInput("ClientHello"));
                	} catch(java.lang.UnsupportedOperationException | java.lang.IllegalArgumentException e) {
                		System.out.println(cs.name() + " UNSUPPORTED");                		
                	}
                }
            } else {
            	connector.startListening();
            }
		} catch(Exception e) {
			System.err.println("Error occured: " + e.getMessage());
			e.printStackTrace(System.err);
			System.exit(1);
		}
	}
}
