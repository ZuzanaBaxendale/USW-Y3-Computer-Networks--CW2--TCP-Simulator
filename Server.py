from State import *
from socket import socket

class Transition:
    def passive_open(self):
        print ("Error!")
        return False

    def syn(self):
        print ("Error!")
        return False

    def ack(self):
        print ("Error!")
        return False

    def rst(self):
        print ("Error!")
        return False

    def syn_ack(self):
        print ("Error!")
        return False

    def close(self):
        print ("Error!")
        return False

    def fin(self):
        print ("Error!")
        return False

    def timeout(self):
        print ("Error!")
        return False

    def active_open(self):
        print ("Error!")
        return False

# Starting state
class Closed(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    # transition to listen state
    def passive_open(self):
        print("Transitioning to listen state!")
        self.CurrentContext.setState("LISTEN")
        return True

    # when the connection states go back to Closed State, this will end the connection
    def trigger(self):
        try:
            self.CurrentContext.connection.close()
            self.connection_address = 0
            print ("Closing connection!")
            return True
        except:
            return False


class Listen(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # listen for connections, then transition to Syn Rcvd state
        print ("Listening for connections")
        self.CurrentContext.listen()
        print ("Transitioning to syn rcvd!")
        self.CurrentContext.setState("SYNRCVD")
        return True


class SynRcvd(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # receive commands using socket library, receive SYN command and send SYN+ACK,
        # Client then sends ACK which then leads to established state
        # if SYN is not received, then transition back to Closed

        command = self.CurrentContext.connection.recv(1024)
        
        if command == "SYN":
            print ("SYN command received...")
            print(("Sending SYN + ACK command to " + str(self.CurrentContext.connection_address)))
            self.CurrentContext.connection.send("SYN+ACK")
            command = self.CurrentContext.connection.recv(1024)
            if command == "ACK":
                print ("Ack command received...")
                print ("Transitioning to established!")
                self.CurrentContext.setState("ESTABLISHED")
            else:
                print ("Error! Transitioning to Closed!")
                return self.CurrentContext.closed()
        else:
            print ("Error! Transitioning to Closed!")
            return self.CurrentContext.closed()
        return True


class Established(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
    # Receive messages from the client,
    # if FIN command sent, send an ACK command, then transition to Close Wait
    # Client sends encrypted messages, so the server decrypts the messages by using the same secret key as the client (Symetric key)
        while True:
            message = self.CurrentContext.connection.recv(1024)
            if message == "FIN":
                print ("FIN command received")
                print(("Sending ACK command to " + str(self.CurrentContext.connection_address)))
                self.CurrentContext.connection.send("ACK")
                print ("Transitioning to Close Wait!")
                self.CurrentContext.setState("CLOSEWAIT")
                return True
            else:
                print(("Received " + message))
                clear_text = self.CurrentContext.encrypt_decrypt(message, "TCPAssignment")
                print(("decrypted version: " + clear_text))



class CloseWait(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # Server sends FIN command,
        # then transitions to Last ACK state to wait for the final Acknowledgement from the client
        print ("Sending FIN command...")
        self.CurrentContext.connection.send("FIN")
        print ("Transitioning to Last ACK!")
        self.CurrentContext.setState("LASTACK")
        return True

class LastAck(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # Server waits for final Acknowledgement from client,
        # once received, then the connection closes thus ending the TCP connection
        command = self.CurrentContext.connection.recv(1024)
        if command == "ACK":
            print ("Last ACK received!")
            print ("Transitioning to Closed!")
            self.CurrentContext.setState("CLOSED")
        return True


class TCPSimulator(StateContext, Transition):
    def __init__(self):
        # all server side variables and states
        self.host = "127.0.0.1"
        self.port = 5000
        self.connection_address = 0
        self.socket = None
        self.availableStates["CLOSED"] = Closed(self)
        self.availableStates["LISTEN"] = Listen(self)
        self.availableStates["SYNRCVD"] = SynRcvd(self)
        self.availableStates["ESTABLISHED"] = Established(self)
        self.availableStates["CLOSEWAIT"] = CloseWait(self)
        self.availableStates["LASTACK"] = LastAck(self)
        # Starting state is closed
        print ("Transitioning to Closed state!")
        self.setState("CLOSED")

    def listen(self):
        # Listen for connections using the socket method
        # tuples are used to bind the host and port which makes them immutable
        self.socket = socket()
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            self.connection, self.connection_address = self.socket.accept()
            return True
        except Exception as err:
            print (err)
            exit()

    def encrypt_decrypt(self, input_text, key):
        # Stream Cipher which can encrypt and decrypt messages using a symmetric key for both client and server
        # XOR operator used to encrypt/decrypt text by setting bit to 1 if only one of two bits is 1
        end_key_pos = len(key)-1
        current_key_pos = 0
        output = ""
        for input_byte in input_text:
            if current_key_pos > end_key_pos:
                current_key_pos = 0

            output_byte = ord(input_byte) ^ ord(key[current_key_pos])
            output += chr(output_byte)

            current_key_pos += 1
        return output

    def closed(self):
        return self.CurrentState.passive_open()

    def synrcvd(self):
        return self.CurrentState.synrcvd()

    def established(self):
        return self.CurrentState.established()

    def closedwait(self):
        return self.CurrentState.closedwait()

    def lastack(self):
        return self.CurrentState.lastack()



if __name__ == "__main__":
    simulator = TCPSimulator()
    simulator.closed()
