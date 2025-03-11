import click
import web_interface.main
import analyzer

@click.command()
@click.option('--file', help='The pcap file to analyze', type=click.Path(exists=True))
@click.option('--web', help='Run the web interface', is_flag=True)
@click.option('--print_dns_map', help='Print the DNS map', is_flag=True, default=False)
@click.option('--print_tree', help='Print the pattern tree', is_flag=True, default=False)
@click.option('--phone_ipv4', help='Set a phone IPv4 address', type=str)
@click.option('--phone_ipv6', help='Set a phone IPv6 address', type=str)
@click.option('--use_phone', help='Authorize phone results to be included in the analysis', is_flag=True, default=False)
@click.option('--force_device', help='Force the use of a device from the list by giving the number', type=int)
@click.option('--force_gateway', help='Force the use of a gateway from the list by giving the number', type=int)
def main(file, web, print_dns_map, print_tree, phone_ipv4, phone_ipv6, use_phone, force_device, force_gateway):
    if web and (file or print_dns_map or print_tree or phone_ipv4 or phone_ipv6 or use_phone or force_device or force_gateway):
        raise click.BadOptionUsage('web', 'Cannot use --web and any other option')
    if not web and not file:
        raise click.BadOptionUsage('web', 'Must use --web or --file')
    if web:
        print('Running web interface')
        web_interface.main.app.run()
    else:
        analyzer.run(file, print_map=print_dns_map, print_tree=print_tree, phone_ipv4=phone_ipv4, phone_ipv6=phone_ipv6, use_phone=use_phone, force_device=force_device, force_gateway=force_gateway)
        
if __name__ == '__main__':
    main()