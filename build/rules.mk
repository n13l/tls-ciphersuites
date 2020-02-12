CC  := $(or ${CC},${CC},gcc)
CXX := $(or ${CXX},${CXX},g++)
AR  := $(or ${AR},${AR},ar)

$(o)/%.o: %.c
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) -MMD $(CFLAGS) -o $@ -c $<
	$(M)CC   $<

$(o)/%.s: %.c
	$(Q)mkdir -p $(dir $@)
	$(Q)echo -S -fverbose-asm $@ $<

$(o)/%.o: %.cc
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CXX) $(CXXFLAGS) -o $@ -c $<
	$(M)CX    $<

$(o)/%: $(o)/%.o
	$(Q)mkdir -p $(dir $@)
	$(M)LD   $(patsubst $(o)/%,%,$@)
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

%.a:
	$(Q)mkdir -p $(dir $@)
	$(M)AR   $(patsubst $(o)/%,%,$@)
	$(Q)rm -f $@
	$(Q)ar rcs $@ $^

%.so:
	$(Q)mkdir -p $(dir $@)
	$(M)LD   $(patsubst $(o)/%,%,$@)
	$(Q)$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS) $(LDFLAGS)

.force:

configure: $(o)/.config
$(o)/.config: .force
	$(Q)mkdir -p $(o)
	$(Q)touch $(o)/.config
#	@echo "target: $(TARGET)"
#	@echo "arch: $(ARCH)"
#	@echo "platform: $(PLATFORM)"
	
.PHONY: configure .force

