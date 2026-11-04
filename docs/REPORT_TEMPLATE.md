# Report outline

1. **Title, team** (names, SRNs), GitHub link, who did what.
2. **Problem and objectives**: dynamic firewall that classifies TCP traffic,
   blocks attackers automatically, recovers them, and logs centrally.
3. **Architecture**: topology diagram (h1–h4, s1, srv, POX, logger), the packet-in → classify →
   detect → block flow, the rule table, and the event path controller → logger.
4. **Implementation**
   - sockets: server threads, semaphore limit, line framing, DATA transfer, logger, EventSender
   - SDN: exact-match flows, drop flows, block rule (priority, hard_timeout), barrier, FlowRemoved
   - detector: sliding window, the three thresholds, escalation for repeat offenders
5. **Environment**: paste the output of `lsb_release -a`, `python3 --version`, `mn --version`,
   `ovs-vsctl --version`, and the POX branch (`cd pox && git branch --show-current`).
6. **Testing**: unit tests, and the system check table (`results/system_check/report.md`).
   Add screenshots of:
   - DENY in the logger
   - BLOCK and BLOCK_ENFORCED in the controller
   - the `priority=60000` rule in `ovs-ofctl dump-flows s1`
   - UNBLOCK after recovery
   - a second block lasting twice as long (offence #2)
7. **Performance evaluation**:
   - the table from `results/experiments/results.md`
   - fig1–fig3
   - static vs dynamic, three conditions, response time vs attack rate, controller packet-ins
   - use `--repeat 3`, so every number is an average of three runs, and say how much the runs varied
8. **Challenging scenarios**: flood, port scan, repeated denied access, repeat offender, logger outage,
   controller failure. Say what happened in each.
9. **Limitations and future work**: IP spoofing, per-IP thresholds (NAT), slow attacks, single
   controller, OpenFlow 1.0, unencrypted logger channel.
10. **Conclusion**: based only on your measured numbers.

Rubric mapping:
- architecture → 2, 3
- sockets → 4
- Mininet + SDN → 3, 4
- socket–SDN integration → 3, 6
- testing → 6
- functionality → 6
- dynamic SDN → 4, 6
- challenging scenario → 8
- performance → 7
- documentation / demo / viva → README, DEMO.md, CODE_WALKTHROUGH.md
