
## Tycoon 2FA – New Attack Technique: ASCII Code QR Code Phishing
## Published: 29.01.2025 / 08:07pm CET

One of the latest techniques employed in two-factor authentication (2FA) phishing is the use of ASCII code QR codes. This blog post analyzes this new attack method, which is part of the **Tycoon 2FA** Phishing-as-a-Service (PhaaS) framework.

### Overview of the Attack Technique

#### Attack Type: QR Code Phishing

QR codes are ubiquitous today and are used in many legitimate applications, from payment services to authentication processes. However, cybercriminals exploit this popularity to conduct phishing attacks. The technique examined uses specially crafted ASCII codes to mimic QR codes, enticing users to disclose sensitive information.

### The Phishing Email

A central component of this attack is the phishing email containing the fake QR code. Below is an example image of such an email content:

![Phishing Email](https://github.com/user-attachments/assets/369b33b5-2a06-48d7-9a65-893d2a81006c)

This email aims to gain the recipients' trust and prompt them to scan the QR code, which initiates a man-in-the-middle (MiTM) phishing attack to capture Office 365 credentials.

### Structure of the Attack

#### Using ASCII Codes to Create QR Codes

While the use of QR codes for phishing attacks is not new, the specific technique analyzed represents an innovative advancement. The attack leverages a preformatted HTML `<pre>` block with a `letter-spacing` of 0 to generate the characteristic appearance of a QR code. This makes it more challenging for security solutions to detect the malicious code.

Here is an example of the HTML code used:

```html
 <pre style="letter-spacing:0;text-align:center;font-size:8px;line-height:normal;"> ▄▄▄▄▄▄▄ ▄▄ ▄▄▄▄ ▄▄ ▄▄▄▄▄▄▄ █ ▄▄▄ █ ██▀█▀ ▄▀▄▀▀▄▄ █ ▄▄▄ █ █ ███ █ ▀███▄▄██▀█▄█▀ █ ███ █ █▄▄▄▄▄█ ▄▀█ ▄▀█ █▀▄ █ █▄▄▄▄▄█ ▄ ▄ █▀ ▀ ▀▄▀▀▄ ▄▄▄▄ ▄▄▄ █▄▀▀ ▄▄█ ▄▄ ▀ ▀██▀▀▀▄ ▄ █ ▀▀ ▀█▀▀█ ▄ █ ▀█▀▄██▄ ▄▀▄ ██▀▀ ▄ █▀▄█▄▄▄▄▀▄▀▀███▄██▀▀█ █▀█▄▄▀▀ █▀▀▄▀ ▄▀▄▄█▀ ▀█▄ ▀█▀ ▄ ▄█ ▀ ███▄▄▄▄▄ ▀█ ▀▄▄▄▀█▄█▀▄█ ▀▄▀▀█ █ ▀▄ ▄▄ ▄▀ ▄▄ ▀▄█ ▀ ▄████ ▄▄▄ ▄▄▄▄▄▄▄ ▀▀▄ █▄▄▄▀▀▄█ ▄ ██▄ █ ▄▄▄ █ ▄█▀▄█ ▄▀ ██▄▄▄█▄ ██ █ ███ █ ▄▄█ ▄▀ █ █▄█▄██▄▀ █▄▄▄▄▄█ ▄█▄▀ █▀█▄ ▀ ██▄▄▀█ ▀ </pre>
```

This ASCII representation mimics a legitimate QR code, tricking users into scanning it and thereby redirecting them to a fake login page.

#### Phishing URL

The URL used in the attack is:

[https[:]//fw8d[.]ocf0asky[.]com/XMazUUEC/](https[:]//fw8d[.]ocf0asky[.]com/XMazUUEC/)

According to [urlscan.io](https://urlscan.io), this URL was first submitted on November 14, 2024. ( https://urlscan.io/search/#domain%3Aocf0asky.com ) Since then, the subdomain has been changed multiple times while the path remains the same. Through searching for Indicators of Compromise (IOC), it was determined that this URL is part of the **Tycoon 2FA** framework, as described by [Validin](https://www.validin.com/blog/tycoon_2fa_analyzing_and_hunting_phishing-as-a-service_domains/).

> "The Tycoon 2FA Phishing-as-a-Service (PhaaS) platform is an advanced tool used by cybercriminals to streamline and scale phishing attacks targeting two-factor authentication (2FA) mechanisms. Tycoon 2FA operates as a service, offering a user-friendly interface, customizable phishing templates, and integrated automation features."

Further details and a previous analysis of Tycoon 2FA by Sekoia TDR and Quentin Bourgue can be found [here](https://www.validin.com/blog/tycoon_2fa_analyzing_and_hunting_phishing-as-a-service_domains/).

See the url in "action" on Any.Run
https://app.any.run/tasks/ed62302d-54d3-4ba0-a10c-536248d338dc

### Structure of the Attack

The attack can be broken down into the following steps:

1. **Sending the Phishing Email:** The attacker sends an email to potential victims containing a fake QR code.
2. **Displaying the QR Code:** By using ASCII characters and specific HTML styles, the QR code is presented to appear legitimate.
3. **Victim Interaction:** The victim scans the QR code, which redirects them to a fake login page.
4. **Data Collection:** The entered login credentials are captured by the attacker and can be used for further attacks or accessing sensitive information.

### Detection and Defense

To detect and prevent this new attack technique, a specialized detection rule was published in my **Sublime Security Detection Feed**. Here is the current rule code:

Feed: https://github.com/padey/Sublime-Detection-Rules/tree/main

Rule: https://github.com/padey/Sublime-Detection-Rules/blob/main/detection-rules/tycoon2fa_qr_ascii.yml

```plaintext
type.inbound
// QR Code with ASCII signs, letter-spacing 0 for display.
and (
  strings.icontains(body.html.raw, '<pre style="letter-spacing:0"')
  or strings.icontains(body.html.raw, 'letter-spacing:0')
  and (
        strings.contains(body.html.raw, "▀")  
        or strings.icontains(body.html.raw, "▁")
        or strings.icontains(body.html.raw, "▂")
        or strings.icontains(body.html.raw, "▃")
        or strings.icontains(body.html.raw, "▄")
        or strings.icontains(body.html.raw, "▅")
        or strings.icontains(body.html.raw, "▆")
        or strings.icontains(body.html.raw, "▇")
        or strings.icontains(body.html.raw, "█")
        or strings.icontains(body.html.raw, "▉")
        or strings.icontains(body.html.raw, "▊")
        or strings.icontains(body.html.raw, "▋")
        or strings.icontains(body.html.raw, "▌")
        or strings.icontains(body.html.raw, "▍")
        or strings.icontains(body.html.raw, "▎")
        or strings.icontains(body.html.raw, "▏")
        or strings.icontains(body.html.raw, "▐")
        or strings.icontains(body.html.raw, "░")
        or strings.icontains(body.html.raw, "▒")
        or strings.icontains(body.html.raw, "▓")
        or strings.icontains(body.html.raw, "▔")
        or strings.icontains(body.html.raw, "▕")
        or strings.icontains(body.html.raw, "▖")
        or strings.icontains(body.html.raw, "▗")
        or strings.icontains(body.html.raw, "▘")
        or strings.icontains(body.html.raw, "▙")
        or strings.icontains(body.html.raw, "▚")
        or strings.icontains(body.html.raw, "▛")
        or strings.icontains(body.html.raw, "▜")
        or strings.icontains(body.html.raw, "▝")
        or strings.icontains(body.html.raw, "▞")
        or strings.icontains(body.html.raw, "▟")
    )
)
and (
    profile.by_sender().prevalence in ("new", "outlier")
    or (
        profile.by_sender().any_messages_malicious_or_spam
        and not profile.by_sender().any_false_positives
        )
)
```

#### How the Detection Rule Works

This rule aims to identify emails that contain a `<pre>` block with `letter-spacing:0` and utilize a variety of ASCII characters typically used in QR codes. Additionally, the rule checks the sender profile to detect emails from new or outlier senders, as well as senders with known malicious or spam messages.
