# Boss Sniffer

This is a web application built on a client-server architecture that allows an agent (client) to inform a boss (server) about the browsing activities of employees within a company. The application utilizes Python libraries such as Scapy, Socket, Requests, and Multi-threading for efficient and effective monitoring.

## Features

- **Agent (Client) Side:**
  - Captures network traffic using Scapy to analyze browsing activities.
  - Extracts relevant information such as URLs, timestamps, and other metadata.
  - Sends the extracted data to the server for further processing.

- **Boss (Server) Side:**
  - Receives browsing data from the agent (client).
  - Analyzes and processes the data to generate reports or take appropriate actions.
  - Provides a user-friendly interface to view the browsing activities of employees.

## Technologies Used

- **Scapy:** A powerful Python library for capturing, analyzing, and manipulating network packets.
- **Socket:** A standard library in Python for handling network communication between the client and server.
- **Requests:** A popular Python library for making HTTP requests, used for sending data from the client to the server.
- **Multi-threading:** Utilized to handle multiple connections concurrently, ensuring efficient data processing.

## Getting Started

To run the web application, follow these steps:

1. Clone the repository to your local machine.
2. Install the required dependencies using `pip` or `conda`.
3. Run the server-side code on the boss machine and the client-side code on the agent machine.
4. Configure the relevant settings such as IP addresses, ports, and data processing rules.
5. Monitor the browsing activities of employees in real-time or view reports generated by the server.

## Contributions

Contributions to this project are welcome! If you encounter any issues or have suggestions for improvements, please create an issue or submit a pull request. We appreciate your contributions to make this web application more robust and user-friendly.

## License

This project is licensed under the [MIT License](LICENSE). Feel free to use, modify, and distribute the code as per the terms of the license.

## Acknowledgements

We would like to thank the creators and contributors of the Scapy, Socket, and Requests libraries for their excellent work in building powerful tools for network communication and data analysis.
