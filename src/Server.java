import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class Server {

    private static final int PORT = 5000;

    private final KeyPair serverKeyPair;
    private final List<ClientHandler> clients = new CopyOnWriteArrayList<>();

    public Server() {
        System.out.println("Generando par de claves RSA del servidor...");
        serverKeyPair = Crypto.generateKeyPair();
        if (serverKeyPair == null) {
            throw new RuntimeException("No se ha podido generar el par de claves del servidor.");
        }
        System.out.println("Claves generadas correctamente.");
    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Servidor escuchando en el puerto " + PORT + "...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Nueva conexion desde: " + clientSocket.getInetAddress());

                ClientHandler handler = new ClientHandler(clientSocket);
                clients.add(handler);
                new Thread(handler).start();
            }

        } catch (IOException ex) {
            System.err.println("Error en el servidor: " + ex.getMessage());
        }
    }

    private void broadcast(String message, ClientHandler sender) {
        for (ClientHandler client : clients) {
            if (client != sender && client.isReady()) {
                client.sendEncryptedMessage(message);
            }
        }
    }

    private void removeClient(ClientHandler handler) {
        clients.remove(handler);
        System.out.println("Cliente desconectado. Clientes activos: " + clients.size());
    }

    private class ClientHandler implements Runnable {

        private final Socket socket;
        private ObjectOutputStream out;
        private ObjectInputStream in;
        private PublicKey clientPublicKey;
        private String clientName = "Anonimo";
        private boolean ready = false;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public boolean isReady() {
            return ready;
        }

        @Override
        public void run() {
            try {
                out = new ObjectOutputStream(socket.getOutputStream());
                in  = new ObjectInputStream(socket.getInputStream());

                out.writeObject(serverKeyPair.getPublic());
                out.flush();

                clientPublicKey = (PublicKey) in.readObject();
                System.out.println("Clave publica recibida del cliente " + socket.getInetAddress());

                byte[] encryptedName = (byte[]) in.readObject();
                byte[] nameBytes = Crypto.decrypt(encryptedName, serverKeyPair.getPrivate());
                if (nameBytes != null) {
                    clientName = new String(nameBytes, "UTF-8");
                }

                ready = true;
                System.out.println("Cliente '" + clientName + "' listo.");
                broadcast("[" + clientName + " se ha conectado al chat]", this);

                while (true) {
                    byte[] encryptedMessage = (byte[]) in.readObject();
                    byte[] messageBytes = Crypto.decrypt(encryptedMessage, serverKeyPair.getPrivate());

                    if (messageBytes == null) {
                        System.err.println("Error descifrando mensaje de " + clientName);
                        continue;
                    }

                    String message = new String(messageBytes, "UTF-8");
                    System.out.println("[" + clientName + "]: " + message);

                    if (message.equalsIgnoreCase("/salir")) {
                        break;
                    }

                    broadcast("[" + clientName + "]: " + message, this);
                }

            } catch (EOFException | SocketException ex) {
            } catch (Exception ex) {
                System.err.println("Error con el cliente " + clientName + ": " + ex.getMessage());
            } finally {
                broadcast("[" + clientName + " ha abandonado el chat]", this);
                removeClient(this);
                try { socket.close(); } catch (IOException ignored) {}
            }
        }

        public void sendEncryptedMessage(String message) {
            try {
                byte[] encrypted = Crypto.encrypt(message.getBytes("UTF-8"), clientPublicKey);
                out.writeObject(encrypted);
                out.flush();
            } catch (Exception ex) {
                System.err.println("Error enviando mensaje a " + clientName + ": " + ex.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        new Server().start();
    }
}