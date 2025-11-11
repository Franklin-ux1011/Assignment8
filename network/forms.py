from django import forms

DHCP_CHOICES = (
    ('DHCPv4', 'DHCPv4'),
    ('DHCPv6', 'DHCPv6'),
)

class DhcpRequestForm(forms.Form):
    mac_address = forms.CharField(label='MAC Address', max_length=17,
                                  help_text='Format: 00:1A:2B:3C:4D:5E')
    dhcp_version = forms.ChoiceField(choices=DHCP_CHOICES)
