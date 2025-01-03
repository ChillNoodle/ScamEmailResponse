from googleapiclient.discovery import build
import base64

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def get_service():
    """Return the Gmail API service assuming authentication is already completed."""
    from google.oauth2.credentials import Credentials
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    return build('gmail', 'v1', credentials=creds)

def get_unread_emails(service):
    """Retrieve all unread emails."""
    results = service.users().messages().list(userId='me', q='is:unread').execute()
    return results.get('messages', [])

def forward_email(service, message_id, recipient):
    """Forward an email to the specified recipient."""
    print(f"Forwarding email with ID {message_id} to {recipient}...")
    # Fetch the email message
    message = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
    raw_message = base64.urlsafe_b64decode(message['raw']).decode('utf-8')
    
    # Modify the raw email to include the forwarding recipient
    forward_message = f"To: {recipient}\n{raw_message}"
    encoded_message = base64.urlsafe_b64encode(forward_message.encode('utf-8')).decode('utf-8')

    try:
        service.users().messages().send(
            userId='me',
            body={'raw': encoded_message}
        ).execute()
        print(f"Email with ID {message_id} successfully forwarded to {recipient}.")
    except Exception as e:
        print(f"Failed to forward email with ID {message_id}: {e}")

def mark_email_as_read(service, message_id):
    """Mark an email as read."""
    print(f"Marking email with ID {message_id} as read...")
    service.users().messages().modify(
        userId='me',
        id=message_id,
        body={'removeLabelIds': ['UNREAD']}
    ).execute()
    print(f"Email with ID {message_id} marked as read.")

def main():
    service = get_service()
    recipient = 'andremarinak99@gmail.com'

    # Get all unread emails
    unread_emails = get_unread_emails(service)
    if not unread_emails:
        print("No unread emails found.")
        return

    for email in unread_emails:
        message_id = email['id']
        print(f"Processing email with ID {message_id}...")
        
        # Forward the email
        forward_email(service, message_id, recipient)

        # Mark the email as read
        mark_email_as_read(service, message_id)

if __name__ == '__main__':
    main()
