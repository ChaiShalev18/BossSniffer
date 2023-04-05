import socket

SERVER_ADDRESS = ('54.71.128.194', 8808)
USER = "chai.hadad"
QUERY = "400#USER=" + USER # First query to the server
UPLOAD_CODE = "700#" 
GOOD_USER_RESPONSE = "405#USER OK" # What the server responses for good request
FILE_DETAILS = 'SIZE={size},HTML={html}' 


def upload_results(path_to_index):
    """
    This function uploads the files to the bossniffer.com server.
    param path_to_index: path to the index.html file on the client (report file)
    type path_to_index: str
    return: None
    rtype: None
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Connecting to Bossniffer Server
    s.connect(SERVER_ADDRESS)

    s.sendall(QUERY.encode())
    answer = s.recv(1024)
    
    if GOOD_USER_RESPONSE in answer.decode():
        try:
            with open(path_to_index, 'r') as html_file:
                data = html_file.read()
                
                to_send = UPLOAD_CODE + FILE_DETAILS.format(size=len(data), html=data)
                print(to_send)
                s.sendall(to_send.encode())
                print(s.recv(1024).decode())
        except:
            print("%s is not readable" % (path_to_index))
        finally:
            s.close()  # End connection with server
			
			
upload_results(input())