#!/usr/bin/python3

import socket
import threading
import select
import sys
import getifaddrs

terminateAll = False

class ClientThread(threading.Thread):
        def __init__(self, clientSocket, targetHost, targetPort):
                threading.Thread.__init__(self)
                self.__clientSocket = clientSocket
                self.__targetHost = targetHost
                self.__targetPort = targetPort

        def run(self):
                #print("Client Thread started")

                self.__clientSocket.setblocking(0)

                targetHostSocket = None

                #print("looking up %s %s" % (localHost, localPort))
                for res in socket.getaddrinfo(self.__targetHost, self.__targetPort, socket.AF_INET6,
                                              socket.SOCK_STREAM, socket.SOL_TCP):
                        af, socktype, proto, canonname, sa = res
                        try:
                                print("trying: %s %s %s %s" % (af, socktype, proto, sa))
                                targetHostSocket = socket.socket(af, socktype, proto)
                                targetHostSocket.connect(sa)
                        except socket.error:
                                if s is not None:
                                        s.close()
                                        s = None

                targetHostSocket.setblocking(0)

                clientData = b""
                targetHostData = b""
                terminate = False
                while not terminate and not terminateAll:
                        inputs = [self.__clientSocket, targetHostSocket]
                        outputs = []

                        if len(clientData) > 0:
                                outputs.append(self.__clientSocket)

                        if len(targetHostData) > 0:
                                outputs.append(targetHostSocket)

                        try:
                                inputsReady, outputsReady, errorsReady = select.select(inputs, outputs, [], 1.0)
                        except Exception as e:
                                print(e)
                                break

                        for inp in inputsReady:
                                if inp == self.__clientSocket:
                                        try:
                                                data = self.__clientSocket.recv(4096)
                                        except Exception as e:
                                                print(e)

                                        if data != None:
                                                if len(data) > 0:
                                                        targetHostData += data
                                                else:
                                                        terminate = True
                                elif inp == targetHostSocket:
                                        try:
                                                data = targetHostSocket.recv(4096)
                                        except Exception as e:
                                                print(e)

                                        if data != None:
                                                if len(data) > 0:
                                                        clientData += data
                                                else:
                                                        terminate = True

                        for out in outputsReady:
                                if out == self.__clientSocket and len(clientData) > 0:
                                        bytesWritten = self.__clientSocket.send(clientData)
                                        if bytesWritten > 0:
                                                clientData = clientData[bytesWritten:]
                                elif out == targetHostSocket and len(targetHostData) > 0:
                                        bytesWritten = targetHostSocket.send(targetHostData)
                                        if bytesWritten > 0:
                                                targetHostData = targetHostData[bytesWritten:]

                self.__clientSocket.close()
                targetHostSocket.close()
                #print "ClienThread terminating"

if __name__ == '__main__':
        if len(sys.argv) != 5:
                print('Usage:\n\tpython SimpleTCPRedirector <host> <port> <remote host> <remote port>')
                print('Example:\n\tpython SimpleTCPRedirector localhost 8080 www.google.com 80')
                sys.exit(0)

        localHost = sys.argv[1]
        localPort = int(sys.argv[2])
        targetHost = sys.argv[3]
        targetPort = int(sys.argv[4])

        serverSocket = None
        if localHost == 'guess':
           nifs = getifaddrs.getifaddrs()
           for ni in nifs:
               if ni.name==b'br-lan' and ni.family==10 and ni.addr[0][0:4]=='fe80':
                  print("Setting localhost %s" % (ni.addr[0]))
                  print("calling socket(%s,%s,%s)" % (ni.family, socket.SOCK_STREAM, socket.SOL_TCP))
                  serverSocket = socket.socket(ni.family, socket.SOCK_STREAM, socket.SOL_TCP)
                  nsa = (ni.addr[0], localPort, ni.addr[2], ni.addr[3])
                  serverSocket.bind(nsa)
                  serverSocket.listen(5)

        else:
                #print("looking up %s %s" % (localHost, localPort))
                for res in socket.getaddrinfo(localHost, localPort, socket.AF_INET6,
                                              socket.SOCK_STREAM, socket.SOL_TCP):
                        af, socktype, proto, canonname, sa = res
                        try:
                                print("trying: %s %s %s %s" % (af, socktype, proto, sa))
                                serverSocket = socket.socket(af, socktype, proto)
                                serverSocket.bind(sa)
                                serverSocket.listen(5)
                        except socket.error:
                                if s is not None:
                                        s.close()
                                        s = None

        if serverSocket is None:
          print('Socket opening/binding failed')
          sys.exit(1)

        while True:
                try:
                        clientSocket, address = serverSocket.accept()
                except KeyboardInterrupt:
                        print("\nTerminating...")
                        terminateAll = True
                        break
                ClientThread(clientSocket, targetHost, targetPort).start()

        serverSocket.close()
