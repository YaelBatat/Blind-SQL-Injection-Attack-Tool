# Blind SQL Injection Attack Tool

## Overview
This project demonstrates a **Boolean-based Blind SQL Injection** attack. The tool is designed to programmatically extract a specific user's password from a MariaDB database by exploiting a vulnerable PHP-based web application. 

The project was developed in **C** with a focus on efficiency, strictly adhering to a constraint of **maximum 100 queries** per extraction.

## Technical Environment
The attack is performed within a controlled Docker environment:
* **Database (MariaDB):** Contains a `users` table with `id` and `password` columns.
* **Web Application:** A PHP site that returns different messages based on whether a query returns data or not ("Your order has been sent!" vs "Your order has not been sent yet").
* **Attacker Container:** Runs the exploit code within an isolated virtual LAN (`bsqli-net`).

## Exploit Strategy
Since the web application does not return direct query results, the tool uses **Boolean-based inference**. By observing the response of the web page to injected payloads, the tool can leak the password one bit or character at a time.

### Key Features:
* **Optimized Query Logic:** Designed to minimize HTTP requests to meet the 100-query limit.
* **Full ASCII Support:** Capable of extracting passwords containing any printable ASCII characters (0x20-0x7F).
* **Strict Compilation:** Developed using rigorous flags to ensure code quality: `-Wall -Wextra -Werror -Wconversion`.

## How to Run

1.  **Start the Environment:**
    Ensure Docker is running and start the containers:
    ```bash
    docker start mariadb-server web-app attacker
    ```

2.  **Access the Attacker Container:**
    ```bash
    docker exec -it attacker /bin/bash
    ```

3.  **Compile the Tool:**
    ```bash
    gcc -Wall -Wextra -Werror -Wconversion ex4.c -o attack
    ```

4.  **Execute:**
    ```bash
    ./attack
    ```

## Project Structure
* `ex4.c`: The core C source code for the attack.
* `explanation.txt`: A detailed breakdown of the injection logic.


---
*Disclaimer: This project was created for educational purposes as part of a Cybersecurity course.*
