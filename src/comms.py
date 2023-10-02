import smtplib
import re
import logging


DESIGN_AND_DELIVERY_DL = 'CORPISDLNetworkDesignDelivery@HCAHealthcare.com'
NETWORK_ADVANCED_SUPPORT_DL = 'CORPISDLNetworkAdvancedSupport@HCAHealthcare.com'
NETWORK_PROACTIVE_DL = 'CorpISDLNetworkProactiveMaintenance@HCAHealthcare.com'


def email_notification(receivers: list, subject: str, msg_text: str):
    sender = 'NetworkAPIs@hcahealthcare.com'

    # Assert that all recipients are HCA recipients
    for receiver in receivers[:]:
        if not re.match(r'[-.\w]+@hcahealthcare.com', receiver):
            receivers.remove(receiver)

    msg_text = msg_text.splitlines()

    message = (
        "From: Network APIs <NetworkAPIs@hcahealthcare.com>\n"
        f"To: {', '.join(receivers)}\n"
        f"Subject: DO NOT REPLY - {subject}\n"
        "Content-Type: text/html\n"
        "\n"
        f"{'<p>'.join(msg_text)}<p>"
        f"<b>Note:</b>  <i>This message was sent from an unmanaged email address.  Any reply will not be answered.<i>"
    )

    try:
        smtp_obj = smtplib.SMTP('smtp-gw.nas.medcity.net')
        smtp_obj.sendmail(sender, receivers, message)
        # logger.debug('Email Sent: Subject: %s to %s' % (subject, receivers))
    except smtplib.SMTPException:
        # logger.debug('Attempt to send email failed: %s to %s' % (subject, receivers))
        return False


def text_message():
    # TODO: Find a way to send a text message
    return None
