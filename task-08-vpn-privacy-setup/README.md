## Objectives
- Configure and connect to ProtonVPN using OpenVPN on Kali Linux.
- Verify VPN connection by checking the changed public IP address.
- Document VPN connection process with screenshots.
- Confirm that traffic is routed through a secure VPN tunnel.

## Connection Details
| Field           | Value                      |
|-----------------|----------------------------|
| VPN Service     | ProtonVPN (Free Plan)      |
| Protocol        | OpenVPN UDP                |
| Server Location | Seattle, Washington, USA   |
| New IP Address  | 149.40.62.9                 |
| ISP             | DataCamp Limited           |

## Steps Performed
1. Logged into the ProtonVPN dashboard.
2. Navigated to **Downloads → OpenVPN configuration files**.
3. Selected **Free Plan**, **UDP**, and **US server**; downloaded `us-free-34.protonvpn.udp.ovpn`.
4. Installed OpenVPN on Kali Linux:
   ```bash
   sudo apt update
   sudo apt install -y openvpn
   ```
5. Connected to the VPN:
   ```bash
   cd ~/Downloads
   sudo openvpn --config us-free-34.protonvpn.udp.ovpn
   ```
6. Entered **OpenVPN username** and **password** from ProtonVPN account.
7. Waited for terminal output: `Initialization Sequence Completed`.
8. Verified new IP at [https://whatismyipaddress.com](https://whatismyipaddress.com).
9. Captured screenshots:
   - **screenshot_vpn_connected.png** – Terminal after successful connection.
   - **screenshot_ip_after.png** – Browser showing new VPN IP location.

## Observations
- Real IP address successfully masked.
- New IP location: Seattle, Washington, USA.
- VPN tunnel encryption active; ISP and local network cannot see browsing activity.
- Minor latency observed but acceptable for secure browsing.

## Conclusion
ProtonVPN was successfully configured on Kali Linux using OpenVPN. The connection encrypted all traffic and changed the public IP, enhancing privacy and security. This setup is effective for secure internet usage on untrusted networks.
