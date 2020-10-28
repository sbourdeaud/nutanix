# region headers
# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    2020/10/16, v1
# task_name:    SendEmail
# description:  Sends an email notification with VM details.
# input:        requester_email, email_sender, smtp_server, vm_requester_name, vm_name
# output:       n/a
# endregion

#region capture Calm variables
$email_to = "@@{requester_email}@@"
$email_from = "@@{email_sender}@@" 
$smtp_server = "@@{smtp_server}@@" 
$requester = "@@{vm_requester_name}@@"
$vm_name = "@@{vm_name}@@"
$vm_ip = "@@{static_ip}@@"
#endregion

#region creating email body
$html_var1 = "<html><body><p>Hello $($requestor),</p><p>You had requested a Windows VM, we have successfully deployed your VM and you can start using it using the following information:</p>"
$html_var2 = "<br>Service type: Windows instance</br>
<br>VM name: $($vm_name)</br>
<br>VM IP address: $($vm_ip)</br>
<br>Login: @@{windows.username}@@</br>
<br>Password: @@{windows.secret}@@</br>
"
$html_var3 = "<p>For security reasons, please do not share your password with anyone.<br>Regards,<br><p>The Cloud Team</p></body></html>"
$email_body = $html_var1 + $html_var2 + $html_var3
#endregion

#region sending email
$email_subject = "Your VM  $($vm_name) is ready!"

try {
    Write-Output ("Sending email notification...")
    Send-MailMessage -From $email_from -To $email_to -Subject $email_subject -BodyAsHtml $email_body -SmtpServer $smtp_server
    Write-Output ("Sending email notification --> Complete")
} catch {
    Write-Output ("Sending email notification --> Error")
    Write-Warning ('Failed to send email: "{0}"', $_.Exception.Message)
}
#endregion