package nl.cypherpunk.tlsattackerconnector;

/**
 * Based on TransportHandler from
 * 
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpNoDelayTransportHandler;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * @author Joeri de Ruiter <joeri@cs.ru.nl>
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ConnectorTransportHandler extends ClientTcpNoDelayTransportHandler {
    public ConnectorTransportHandler(long timeout, String hostname, int port) throws SocketException {
        super(timeout, hostname, port);
    }    

    @Override    
    public byte[] fetchData() throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        
        if(isClosed()) {
        	return stream.toByteArray();
        }        
        
        long minTimeMillies = System.currentTimeMillis() + timeout;
        while ((System.currentTimeMillis() < minTimeMillies) && (stream.toByteArray().length == 0)) {
        	inStream.mark(1);
        	int test = inStream.read();
        	if(test == -1) {
        		// Socket is no longer usable, so close it properly
        		closeClientConnection();
        		return stream.toByteArray();
        	}
        	inStream.reset();  
        	
        	while (inStream.available() != 0) {
                int read = inStream.read();
                
	            if(read == -1) {
	            	System.out.println("Closing socket");
	            	// Properly close the socket if the end of the stream was reached
	            	closeClientConnection();
	            	return stream.toByteArray();
	            }

	            stream.write(read);	            	
            }
        }
        return stream.toByteArray();    	
    }
    
    @Override
    public void initialize() throws IOException {
        socket = new Socket(hostname, port);
        // Set timeout so reads won't block forever
        socket.setSoTimeout((int) timeout);
        
        // Use BufferedStreams so we can mark and look ahead
        BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
        BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
        
        setStreams(bis, bos);
    }    
}

