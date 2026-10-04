import email
from email import policy
import re
from typing import Dict, Any, List

def parse_email(file_path: str) -> Dict[str, Any]:
    """
    Parses a raw .eml file into a structured dictionary.

    Forensic Significance of Headers:
    - Sender (From): Who the email claims to be from. Often spoofed in phishing.
    - Subject: The topic of the email.
    - Message-ID: A unique identifier for the email assigned by the originating mail server.
    - Reply-To: The address that replies should be sent to. Often manipulated in BEC (Business Email Compromise)
      to direct replies to an attacker instead of the legitimate sender.
    - Return-Path: The address where bounce messages are sent. If this doesn't match the Sender, it might be suspicious.
    - Received: A trace of all Mail Transfer Agents (MTAs) the email passed through. Essential for finding the true origin.
    - Authentication-Results / DKIM-Signature / Received-SPF: Contains raw validation info. We extract this to later
      evaluate if the sender is authorized to send on behalf of the domain.

    Args:
        file_path (str): The path to the .eml file.

    Returns:
        dict: A structured dictionary containing parsed email fields.
    """
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except Exception as e:
        # In case of file reading errors or total parse failure, return a safe fallback.
        return {"error": f"Failed to parse email: {str(e)}"}

    # Extract sender information
    # The 'From' header might look like: "John Doe" <john@example.com>
    from_header = msg.get('From', 'unknown')
    
    # We can do a rudimentary split for display name and email if desired,
    # but the email module's 'addresses' property makes this easier if available.
    # However, for robustness against malformed headers, we can just return the raw string
    # or try to extract it manually.
    display_name = "unknown"
    sender_email = "unknown"
    if from_header != 'unknown':
        import email.utils
        parsed_name, parsed_addr = email.utils.parseaddr(from_header)
        display_name = parsed_name if parsed_name else "unknown"
        sender_email = parsed_addr if parsed_addr else "unknown"

    # Extract standard headers safely
    subject = msg.get('Subject', 'unknown')
    message_id = msg.get('Message-ID', 'unknown')
    reply_to = msg.get('Reply-To', 'unknown')
    return_path = msg.get('Return-Path', 'unknown')

    # Extract bodies (Text and HTML)
    body_text = "unknown"
    body_html = "unknown"
    
    # The message might be multipart or single part
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get_content_disposition())
            
            if content_type == 'text/plain' and 'attachment' not in content_disposition:
                try:
                    body_text = part.get_content()
                except Exception:
                    pass
            elif content_type == 'text/html' and 'attachment' not in content_disposition:
                try:
                    body_html = part.get_content()
                except Exception:
                    pass
    else:
        # Not multipart
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
            if content_type == 'text/html':
                body_html = content
            else:
                body_text = content
        except Exception:
            pass

    # Extract all 'Received' headers in order
    # The email library's `get_all` returns them in the order they appear (top to bottom).
    # Since MTAs prepend Received headers, the top one is the last hop (closest to receiver).
    received_headers = msg.get_all('Received', [])

    # Extract raw Auth headers
    spf_header = msg.get('Received-SPF', 'unknown')
    dkim_header = msg.get('DKIM-Signature', 'unknown')
    dmarc_header = msg.get('DMARC-Filter', 'unknown') # Varies; sometimes embedded in Authentication-Results
    auth_results = msg.get('Authentication-Results', 'unknown')

    return {
        "sender": sender_email,
        "display_name": display_name,
        "subject": subject,
        "body_text": body_text,
        "body_html": body_html,
        "received_headers": received_headers,
        "message_id": message_id,
        "reply_to": reply_to,
        "return_path": return_path,
        "auth_headers": {
            "spf": spf_header,
            "dkim": dkim_header,
            "dmarc_filter": dmarc_header,
            "authentication_results": auth_results
        }
    }


def reconstruct_hop_path(received_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Analyzes the 'Received' headers chain to reconstruct the SMTP relay hop path.

    Forensic Significance:
    - By tracing the 'Received' headers from bottom (origin) to top (destination),
      we can find the true IP address where the email originated.
    - Attackers often forge the bottom-most 'Received' headers to make an email look
      like it came from a legitimate server. Inconsistencies in the chain can reveal spoofing.

    Args:
        received_headers (list): A list of raw Received header strings (top to bottom).

    Returns:
        list: An ordered list of hops (from origin to destination).
    """
    hops = []
    
    # We iterate in reverse because standard email prepends headers. 
    # Reversing it gives us chronological order (origin -> destination)
    # i.e., hop_number 1 is where the email originated.
    for idx, header in enumerate(reversed(received_headers)):
        # Initialize defaults
        from_host = "unknown"
        by_host = "unknown"
        timestamp = "unknown"
        extracted_ip = "unknown"

        # Regex patterns to extract data from a typical Received header:
        # e.g., "from sender.domain.com (sender.domain.com [192.168.1.1]) by mta.receiver.com ... ; Tue, 1 Jan 2026 12:00:00 +0000"
        
        # 1. Extract 'from' host
        from_match = re.search(r'from\s+([^\s]+)', header, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1)

        # 2. Extract 'by' host
        by_match = re.search(r'by\s+([^\s;]+)', header, re.IGNORECASE)
        if by_match:
            by_host = by_match.group(1)

        # 3. Extract IP address (looks for IPv4)
        # In a real scenario, we might also look for IPv6.
        ip_match = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', header)
        if ip_match:
            extracted_ip = ip_match.group(1)

        # 4. Extract timestamp (usually after the last semicolon)
        parts = header.rsplit(';', 1)
        if len(parts) == 2:
            timestamp = parts[1].strip().replace('\r', '').replace('\n', '')

        hops.append({
            "hop_number": idx + 1,
            "from_host": from_host,
            "by_host": by_host,
            "timestamp": timestamp,
            "extracted_ip": extracted_ip,
            "raw": header.strip().replace('\r', '').replace('\n', ' ')
        })

    return hops
