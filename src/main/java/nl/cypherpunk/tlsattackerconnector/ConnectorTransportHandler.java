package nl.cypherpunk.tlsattackerconnector;

/**
 * Based on SimpleTransportHandler from
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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * @author Joeri de Ruiter <joeri@cs.ru.nl>
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ConnectorTransportHandler extends TransportHandler {

    private Socket socket;

    private ServerSocket serverSocket;

    private boolean isServer = false;

    private BufferedOutputStream bos;

    private BufferedInputStream bis;

    public ConnectorTransportHandler(String hostname, int port, ConnectionEndType end, int socketTimeout) {
        super(hostname, port, end, socketTimeout);
    }

    @Override
    public void initialize() throws IOException {
        if (end == ConnectionEndType.SERVER) {
            serverSocket = new ServerSocket(port);
            LOGGER.info("Starting ServerTransportHandler on Port:" + port);
            isServer = true;
            socket = serverSocket.accept();
            LOGGER.info("Acception connection from:" + socket.toString());
        } else {
            LOGGER.info("Connecting to " + hostname + ":" + port);
            socket = new Socket(hostname, port);
            LOGGER.info("Connected.");
        }

        socket.setSoTimeout(socketTimeout);
        socket.setTcpNoDelay(true);
        
        OutputStream os = socket.getOutputStream();
        bos = new BufferedOutputStream(os);

        InputStream is = socket.getInputStream();
        bis = new BufferedInputStream(is);
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        LOGGER.debug("Sending data:" + ArrayConverter.bytesToHexString(data));
        try {
            bos.write(data);
        	bos.flush();
        } catch (SocketException ex) {
            // While connecting to a Java server, a "Connection reset" failure
            // was received.Connection reset means that a TCP packet with the
            // RST bit was received. The most common cause of this is an attempt
            // to send to a partner that has closed its socket
            LOGGER.debug("SocketException occured, so closing socket.");
            
            // Properly close the socket if an exception occurred so we can detect that it cannot be used anymore
        	socket.close();            
        }
    }

    @Override
    public byte[] fetchData() throws IOException {
        byte[] response = new byte[0];
        
        if(socket.isClosed()) {
        	return response;
        }

        long minTimeMillies = System.currentTimeMillis() + socketTimeout;
        // long maxTimeMillies = System.currentTimeMillis() + timeout;
        while ((System.currentTimeMillis() < minTimeMillies) && (response.length == 0)) {
            // Try to read one byte to be able to detect whether the socket is still open
        	bis.mark(1);
        	int test = bis.read();
        	if(test == -1) {
        		// Socket is no longer usable, so close it properly
        		socket.close();
        		return response;
        	}
        	bis.reset();
        	
            while (bis.available() != 0) {
                // TODO: It is never correct to use the return value of this
                // method to allocate a buffer intended to hold all data in this
                // stream.
                // http://docs.oracle.com/javase/7/docs/api/java/io/InputStream.html#available%28%29
                byte[] current = new byte[bis.available()];
                int readResult = bis.read(current);
                if (readResult != -1) {
                    response = ArrayConverter.concatenate(response, current);
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException ex) {

                    }
                } else {
                    // Properly close the socket if the end of the stream was reached
                	socket.close();
                }
            }
        }
        if (isServer) {
            LOGGER.debug("Accepted {} new bytes from client", response.length);
        } else {
            LOGGER.debug("Accepted {} new bytes from server", response.length);
        }
        return response;
    }

    @Override
    public void closeConnection() {
        try {
            if (bos != null) {
                bos.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
        try {
            if (bis != null) {
                bis.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            LOGGER.debug(e);
        }
    }

    public boolean isSocketClosed() throws IOException {
        return socket.isClosed();
    }
}

