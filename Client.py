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


class Closed(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def active_open(self):
        # Make a connection to an open socket and get commands from a text file which will enable the sending of commands
        # Send a SYN command to the Server to initiate the three way handshake
        self.CurrentContext.connection()
        self.CurrentContext.get_commands("client_commands.txt")
        print(("Connecting to " + str(self.CurrentContext.connection_address)))
        print(("sending syn command to " + str(self.CurrentContext.connection_address)))
        #   send SYN command...
        self.CurrentContext.socket.send(self.CurrentContext.commands[0])

        print ("Transitioning to Syn Sent State!")
        self.CurrentContext.setState("SYNSENT")
        return True

    def trigger(self):
        #  this is used when the last ACK has been received by the server
        try:
            self.CurrentContext.socket.close()
            self.connection_address = 0
            print ("Closing connection!")
            return True
        except:
            return False


# CLIENT SIDE CLASSES

class SynSent(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # Wait for SYN+ACK command using socket receive
        # send ACK command which then leads to the Established state
        # if SYN+ACK not sent, then go back to closed
        command = self.CurrentContext.socket.recv(1024)
        if command == "SYN+ACK":
            print(("Syn + ack command received from " + str(self.CurrentContext.connection_address)))
            print(("Sending ack command to " + str(self.CurrentContext.connection_address)))
            #   send ACK command
            self.CurrentContext.socket.send(self.CurrentContext.commands[1])
            print ("Transitioning to established!")
            self.CurrentContext.setState("ESTABLISHED")
        else:
            print ("Timeout Occured! Transitioning to Closed!")
            return self.CurrentContext.closed()
        return True

class Established(Transition, State):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # Send messages to the server which are then encrypted using
        # XOR and a Symmetrical key to allow both encryption and decryption
        # if the input is close, then send a FIN command to the server to Transition to Fin Wait 1
        input_text = input("Message: ")
        while input_text != "close":
            encrypted_text = self.CurrentContext.encrypt_decrypt(input_text, "TCPAssignment")
            print(("Sending: " + str(encrypted_text)))
            self.CurrentContext.socket.send(encrypted_text)
            input_text = input("Message: ")
        if input_text == "close":
            print(("Sending FIN command to " + str(self.CurrentContext.connection_address)))
            self.CurrentContext.socket.send(self.CurrentContext.commands[2])
            print ("Transitioning to Fin Wait 1!")
            self.CurrentContext.setState("FINWAIT1")


class FinWait1(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # Waits for an Acknowledgement from the Server
        # This then leads to the Fin Wait 2 state
        command = self.CurrentContext.socket.recv(1024)
        if command == "ACK":
            print ("ACK command received!")
            print ("Transitioning to FIN Wait 2!")
            self.CurrentContext.setState("FINWAIT2")
        return True


class FinWait2(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # Uses socket to receive data from the server
        # once a FIN command is sent from the server, then send the last ACK to transition to Timed Wait
        command = self.CurrentContext.socket.recv(1024)
        if command == "FIN":
            print ("FIN command received!")
            print(("Sending ACK command to " + str(self.CurrentContext.connection_address)))
            self.CurrentContext.socket.send(self.CurrentContext.commands[1])
            print ("Transitioning to Timed Wait")
            self.CurrentContext.setState("TIMEDWAIT")
        return True



class TimedWait(State, Transition):
    def __init__(self, Context):
        State.__init__(self, Context)

    def trigger(self):
        # Transition back to closed, Once in closed class, the connection will be closed down
        print ("Transitioning to Closed!")
        self.CurrentContext.setState("CLOSED")
        return True



class TCPSimulator(StateContext, Transition):
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 5000
        self.connection_address = 0
        self.socket = None
        self.commands = []
        self.availableStates["CLOSED"] = Closed(self)
        self.availableStates["ESTABLISHED"] = Established(self)
        self.availableStates["SYNSENT"] = SynSent(self)
        self.availableStates["FINWAIT1"] = FinWait1(self)
        self.availableStates["FINWAIT2"] = FinWait2(self)
        self.availableStates["TIMEDWAIT"] = TimedWait(self)
        print ("Transitioning to Closed state!")
        self.setState("CLOSED")

    def connection(self):
        # this method connects to an open socket
        # the host and port represent the address to connect to
        self.socket = socket()
        try:
            self.socket.connect((self.host, self.port))
            self.connection_address = self.host
        except Exception as err:
            print (err)
            exit()

    def get_commands(self):
        #This method loads the client commands from a text file as a list
        #the lines from the text file are appended to the commands list
        try:
            with open(filename, 'r') as client_commands:
                for line in client_commands:
                    self.commands.append(line.decode())
        except:
            print ("File not found!")
            return False
        return self.commands     

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
        return self.CurrentState.active_open()

    def established(self):
        return self.CurrentState.established()

    def synsent(self):
        return self.CurrentState.synsent()

    def finwait1(self):
        return self.CurrentState.finwait1()

    def finwait2(self):
        return self.CurrentState.finwait2()

    def timedwait(self):
        return self.CurrentState.timedwait()

if __name__ == "__main__":
    simulator = TCPSimulator()
    simulator.closed()
