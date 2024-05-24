import smtplib
from email.message import EmailMessage

def email_alert(subject, body, to):
    msg= EmailMessage()
    msg.set_content(body)
    msg['subjecy'] = subject
    msg['to'] = to
    # GMAIL Account
    user = "email_alert@gmail.com"
    msg['from'] = user
    password = 'P@ssw0rd' # if your use 2 factor use app password
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(user,password)
    server.send_message(msg)
    server.quit()

if __name__ == '__main__':
    email_alert("HEY","Helloworld" "to_mail@gmail.com")