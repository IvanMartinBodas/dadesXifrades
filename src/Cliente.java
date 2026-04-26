import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Scanner;

public class Cliente {

    private static final String HOST = "localhost";
    private static final int    PORT = 5000;

    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream  in;

    private final KeyPair clientKeyPair;
    private PublicKey serverPublicKey;

    public Cliente() {
        System.out.println("Generando par de claves RSA del cliente...");
        clientKeyPair = Crypto.generateKeyPair();
        if (clientKeyPair == null) {
            throw new RuntimeException("No se ha podido generar el par de claves del cliente.");
        }
        System.out.println("Claves generadas correctamente.");
    }

    public void connect(String name) {
        try {
            socket = new Socket(HOST, PORT);
            out = new ObjectOutputStream(socket.getOutputStream());
            in  = new ObjectInputStream(socket.getInputStream());

            System.out.println("Conectado al servidor " + HOST + ":" + PORT);

            serverPublicKey = (PublicKey) in.readObject();
            System.out.println("Clave publica del servidor recibida.");

            out.writeObject(clientKeyPair.getPublic());
            out.flush();

            byte[] encryptedName = Crypto.encrypt(name.getBytes("UTF-8"), serverPublicKey);
            out.writeObject(encryptedName);
            out.flush();

            System.out.println("Intercambio de claves completado. Bienvenido/a al chat, " + name + "!");
            System.out.println("Escribe '/salir' para desconectarte.\n");

            Thread listener = new Thread(this::listenForMessages);
            listener.setDaemon(true);
            listener.start();

            Scanner scanner = new Scanner(System.in);
            while (scanner.hasNextLine()) {
                String message = scanner.nextLine();
                sendEncryptedMessage(message);

                if (message.equalsIgnoreCase("/salir")) {
                    break;
                }
            }

        } catch (ConnectException ex) {
            System.err.println("No se ha podido conectar al servidor. Esta encendido?");
        } catch (Exception ex) {
            System.err.println("Error en el cliente: " + ex.getMessage());
        } finally {
            disconnect();
        }
    }

    private void listenForMessages() {
        try {
            while (true) {
                byte[] encryptedMessage = (byte[]) in.readObject();
                byte[] messageBytes = Crypto.decrypt(encryptedMessage, clientKeyPair.getPrivate());

                if (messageBytes != null) {
                    System.out.println(new String(messageBytes, "UTF-8"));
                } else {
                    System.err.println("[Error descifrando un mensaje recibido]");
                }
            }
        } catch (EOFException | SocketException ex) {
            System.out.println("Conexion con el servidor cerrada.");
        } catch (Exception ex) {
            System.err.println("Error escuchando mensajes: " + ex.getMessage());
        }
    }

    private void sendEncryptedMessage(String message) {
        try {
            byte[] encrypted = Crypto.encrypt(message.getBytes("UTF-8"), serverPublicKey);
            out.writeObject(encrypted);
            out.flush();
        } catch (Exception ex) {
            System.err.println("Error enviando el mensaje: " + ex.getMessage());
        }
    }

    private void disconnect() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ignored) {}
        System.out.println("Desconectado del servidor.");
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Introduce tu nombre: ");
        String name = scanner.nextLine().trim();

        if (name.isEmpty()) {
            name = "Anonimo";
        }

        new Cliente().connect(name);
    }
}