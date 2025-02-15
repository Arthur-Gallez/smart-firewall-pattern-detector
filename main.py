import click
import web_interface.main
import analyzer

@click.command()
@click.option('--file', help='The pcap file to analyze', type=click.Path(exists=True))
@click.option('--web', help='Run the web interface', is_flag=True)
@click.option('--print_dns_map', help='Print the DNS map', is_flag=True, default=False)
@click.option('--print_tree', help='Print the pattern tree', is_flag=True, default=False)
def main(file, web, print_dns_map, print_tree):
    if web and (file or print_dns_map or print_tree):
        raise click.BadOptionUsage('web', 'Cannot use --web and any other option')
    if not web and not file:
        raise click.BadOptionUsage('web', 'Must use --web or --file')
    if web:
        print('Running web interface')
        web_interface.main.app.run()
    else:
        analyzer.run(file, print_map=print_dns_map, print_tree=print_tree)
        
if __name__ == '__main__':
    main()