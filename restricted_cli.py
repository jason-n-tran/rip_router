from mininet.cli import CLI
from mininet.log import info, error
import sys

class RestrictedCLI(CLI):
    """
    A restricted CLI for the router demo.
    Disallows arbitrary shell execution and restricts node commands to a whitelist.
    """

    # Commands that can be run directly in the CLI
    allowed_global_cmds = ['help', 'exit', 'quit', 'net', 'links', 'nodes', 'pingall', 'pingallfull', 'dump', 'intfs']
    
    # Commands that can be run on nodes (e.g., "client ping ...")
    allowed_node_cmds = [
        'ping', 'traceroute', 'wget', 'curl', 'iperf', 
        'arp', 'route', 'ifconfig', 'ip', 'netstat',
        'tcpdump', 'tshark', 'arping'
    ]

    def __init__(self, mininet, stdin=sys.stdin, script=None, **kwargs):
        CLI.__init__(self, mininet, stdin=stdin, script=script, **kwargs)

    def onecmd(self, line):
        """
        Overridden to enforce the whitelist of allowed global commands.
        Any command not in allowed_global_cmds OR not a node command is blocked.
        """
        cmd, arg, line = self.parseline(line)
        if not cmd:
            return self.emptyline()
        
        # Check if it's a whitelisted global command
        if cmd in self.allowed_global_cmds:
            return CLI.onecmd(self, line)

        # Check if it's a node/host
        if cmd in self.mn:
            return self.default(line)

        # Block everything else
        error("Secure Mode: Command '%s' is not allowed.\n" % cmd)
        return False

    def do_sh(self, line):
        error("Shell execution (sh) is disabled for security.\n")

    def do_py(self, line):
        error("Python execution (py) is disabled for security.\n")

    def do_px(self, line):
        error("Python execution (px) is disabled for security.\n")

    def do_xterm(self, line):
        error("Xterm is disabled in this web environment.\n")

    def do_x(self, line):
        error("Xterm is disabled.\n")
        
    def do_gterm(self, line):
        error("Gterm is disabled.\n")

    def do_g(self, line):
        error("Gterm is disabled.\n")

    def parse(self, line):
        """
        Parse input line into (node, rest_of_line) or (None, line).
        Matches Mininet's expected signature for CLI.default compatibility.
        """
        args = line.split()
        if args and args[0] in self.mn:
            node = args[0]
            rest = line[len(node):].strip()
            return node, rest, line
        return None, line, line

    def default(self, line):
        """
        Overridden default handler for node commands.
        Verifies command whitelist and checks for shell injection.
        """
        node_name, rest, line = self.parse(line)
        
        if node_name in self.mn:
            node = self.mn[node_name]
            
            args = rest.split()
            if not args:
               error("Please provide a command to run on %s\n" % node_name) 
               return

            cmd_name = args[0]
            cmd_args = args[1:]
            
            # Simple check: command must be in whitelist
            if cmd_name not in self.allowed_node_cmds:
                error("Secure Mode: Command '%s' is not allowed on node '%s'.\n" % (cmd_name, node_name))
                error("Allowed commands: %s\n" % ", ".join(self.allowed_node_cmds))
                return

            # SECURITY: Check for shell injection characters in arguments
            # Added more comprehensive list of metacharacters
            dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '<', '>', '\\', '!', '"', "'", '*', '?', '[', ']', '{', '}', '~', '#']
            for arg in cmd_args:
                for char in dangerous_chars:
                    if char in arg:
                        error("Secure Mode: Shell metacharacter '%s' detected and blocked.\n" % char)
                        return
                        
            # SECURITY: Block data exfiltration and dangerous flags
            if cmd_name == 'wget':
                forbidden = ['-O', '--output-document', '-o', '--output-file', 
                             '--append-output', '--config', '--post-file', '--post-data']
                for arg in cmd_args:
                    if any(arg == f or arg.startswith(f + '=') or (f.startswith('--') and arg.startswith(f)) for f in forbidden):
                         error("Secure Mode: Wget flag '%s' is blocked.\n" % arg)
                         return
                    if arg.startswith('-O') or arg.startswith('-o'):
                         error("Secure Mode: Wget output flags are blocked.\n")
                         return
                         
            elif cmd_name == 'curl':
                forbidden = ['-o', '--output', '-O', '--remote-name', '-D', '--dump-header', 
                             '-c', '--cookie-jar', '-T', '--upload-file', '--config', '-F', '--form']
                for arg in cmd_args:
                    if any(arg == f or arg.startswith(f + '=') or (f.startswith('--') and arg.startswith(f)) for f in forbidden):
                         error("Secure Mode: Curl flag '%s' is blocked.\n" % arg)
                         return
                    if arg.startswith('-o') or arg.startswith('-O') or arg.startswith('-T') or arg.startswith('-D'):
                         error("Secure Mode: Curl output/upload flags are blocked.\n")
                         return
                    if arg.startswith('@') or '=@' in arg:
                         error("Secure Mode: Curl file reference (@) is blocked.\n")
                         return
            
            elif cmd_name in ['tcpdump', 'tshark']:
                forbidden = ['-w', '-r', '-z', '-F']
                for arg in cmd_args:
                    if any(arg.startswith(f) for f in forbidden):
                         error("Secure Mode: %s flag '%s' is blocked.\n" % (cmd_name.capitalize(), arg))
                         return

            elif cmd_name == 'ip':
                if any(arg.startswith('-b') or arg.startswith('--batch') for arg in cmd_args):
                     error("Secure Mode: IP batch mode is blocked.\n")
                     return
            
            elif cmd_name == 'ping':
                if any(arg == '-f' or arg.startswith('-f') for arg in cmd_args):
                     error("Secure Mode: Flood ping is blocked.\n")
                     return

            # Allow the execution
            # Re-calling CLI.default with our fixed parse will work correctly
            CLI.default(self, line)
            return

        error("Unknown or forbidden command: %s\n" % node_name)

    def do_source(self, line):
        error("Sourcing files is disabled for security.\n")
        
    def do_dpctl(self, line):
        error("dpctl is disabled for security.\n")

