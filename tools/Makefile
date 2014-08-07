TOOL_BINS = tools/make-peer-packet tools/spv-blocks

default-tools:
	@echo Run make tools from top dir. >&2 && exit 1

tools: $(TOOL_BINS)

tools/make-peer-packet: tools/make-peer-packet.o netaddr.o tal_packet.o marshal.o minimal_log.o $(CCAN_OBJS)

clean: tools-clean
distclean: tools-distclean

tools-clean:
	$(RM) $(TOOL_BINS) tools/*.o

tools-distclean:
