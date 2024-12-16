# Veeam Decoys
**Author**: Marco Escobar marco.escobar@veeam.com

This is an **open-source** project where multiple decoys have been created for various Veeam services and remote administration services to detect Discovery (TA0007) and Lateral Movements (TA0008) of threat actors within the organization's **internal** networks.

- Veeam Backup Server
- Veeam Hardened Repository
- Veeam Windows Repository
- Veeam Backup Enterprise Manager
- SSH
- Remote Desktop (RDP)
- Netbios

And the following characteristics:

- Terminal User Interface
- Logs
- Log Forwarding to SysLog Server
- Email Notifications
- Multiple Network Interface Configuration
- List of Used Ports
- Service Management
- Configuration File Editing
- Remote Management


Each service allows for the detection of connection attempts and scans to the different ports used by each service, capturing credentials, IP addresses, source ports, source IP addresses, and specific queries to certain services. All captures are generated in Syslog format to be forwarded to a centralized Syslog server or to send notifications by email.
Additionally, this solution supports the use of multiple network interfaces, it's possible to implement the services across multiple networks, thus allowing for a distributed deployment of the services. 

### Virtual Hardware Requirements | OVA

The minimum requirements needed to use the Appliance are as follows:
- **Processor**: 1 vCPU
- **RAM**: 2 GB 
- **Storage**: 50 GB
- **Network**: 1 GB / VMXNET 3
- **Hypervisor**: vSphere 8.0 or higher.

**Download OVA**: https://dl.24xsiempre.com/DecoyV1.ova

### Rocky Linux Requirements | Manual Installation

- **Operating System**: Minimal installation of Rocky Linux 9.4  
- **Processor**: 1 CPU 
- **RAM**: 2 GB 
- **Storage**: 50 GB 
- **Network**: 1 GB / 10 GB 
- **Firewall**: Disabled 
- **SELinux**: Disabled

# 📗 Documentation

- **Download Documentation English**: https://dl.24xsiempre.com/Decoy_Manual_EN.pdf
- **Descarga Documentación Español**: https://dl.24xsiempre.com/Decoy_Manual_ES.pdf

# Manual Installation

Install Rocky Linux 9.4, choose "Minimal Installation" under the software selection section, make sure that no "Security Profile" is selected, after installation, connect via SSH with user "root" and execute:

`curl -s https://raw.githubusercontent.com/VeeamHub/veeam-decoy/master/install.sh | bash`

Then, access the TUI via SSH (port 41325) or Web Console and edit the "Decoy Config File" to change the name(s) of the interfaces for the Decoy services. Save and restart the services for proper operation.

# Operating System Updates

Appliance: Rocky Linux operating system updates must be performed according to the company's security policies or the appliance user. **It is not this project's responsibility to maintain operating system updates**.
Manual: Installation must comply with company policies.

# Questions
If you have any questions or if something is unclear, please don't hesitate to [create an issue](https://github.com/mescobarcl/hnp/issues) and let us know!

# License
- [MIT License](https://github.com/mescobarcl/hnp/blob/main/LICENSE)
