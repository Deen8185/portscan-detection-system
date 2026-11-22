"""Convert one pcap capture into a CSV of flows with the Python CICFlowMeter.

    /opt/cicflowmeter/bin/python lab/pcap_to_flows.py capture.pcap flows.csv

The `cicflowmeter -f` command in version 0.5.0 passes its arguments to
create_sniffer() in the wrong positions (the verbose flag lands in
`fields`) and crashes, so this wrapper calls the library with keyword
arguments and then flushes the remaining flows exactly as the tool does.
"""

import sys

from cicflowmeter.sniffer import create_sniffer


def main(pcap: str, csv: str) -> None:
    sniffer, session = create_sniffer(input_file=pcap, input_interface=None,
                                      output_mode="csv", output=csv)
    sniffer.start()
    try:
        sniffer.join()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        sniffer.join()
        session.flush_flows()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
