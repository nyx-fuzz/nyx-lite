# script to clean up the the output of ptrace for debugging purposes
# export RUST_BACKTRACE=1 && cargo build --release && strace -k -f -o syscalls_snapshot -- ../target/release/nyx_lite_main --config vmconfig.json --snapshot 

class Event
  attr_accessor :id, :syscall, :stacktrace
  def initialize(id, syscall)
    @id = id
    @stacktrace = []
    @syscall = syscall
  end

  def inspect
    return "  KVM RUN"  if is_run?
    return "   KVM RUN"  if @syscall.include? "KVM_RUN <unfinished "
    return "  KVM GET_REGS" if is_get_regs?
    return "  KVM SET_REGS" if is_set_regs?
    return "  KVM SET_DEBUG" if is_set_debug?
    if is_event_write?
      return "  EVENT_WRITE(#{is_event_write?})"
    end
    if is_lseek?
      return "  LSEEK(#{is_lseek?})"
    end
    serial = serial_print
    if serial
      return "#{@id} print #{serial}"
    end
    stack = "\n"+(1..3).map{|i| short_stackframe(i)}.join("\n")
    lame = %w{epoll_wait resumed unfinished}
    stack = "" if lame.any?{|p| @syscall.include? p}
    stack = ""
    return "#{@syscall}"+stack
    return "#{@id} #{@syscall}"+stack
  end

  def short_stackframe(i)
    return "" if i >= @stacktrace.length
    frame = @stacktrace[i]
    path,call = *frame.split("(")
    bin = path.split("/")[-1]
    fn =call.split("+")[0]
    return " > #{bin} #{fn}"
  end

  def is_run?
    @syscall.include? "ioctl(13, KVM_RUN, 0)"
  end
  
  def is_get_regs?
    @syscall.include? "KVM_GET_REGS"
  end

  def is_set_regs?
    @syscall.include? "KVM_SET_REGS"
  end

  def is_set_debug?
    @syscall.include? "KVM_SET_GUEST_DEBUG"
  end

  def is_event_write?
    if @syscall =~ /write\((\d+), "\\1\\0\\0\\0\\0\\0\\0\\0", 8\) = 8/
      return $1
    end
    return nil
  end

  def is_lseek?
    if @syscall =~/lseek\(5, (\d+)/
      return $1
    end
    return nil
  end

  def serial_print
    if @syscall =~ /write\(1, "(([^"]|\\")*)"(\.\.\.)?, \d+\)/
      return $1
    end
    return nil
  end
end

events = []
replacements = []

File.open(ARGV[0]).each_with_index do |line,i|
  if line.start_with?(" >")
    events[-1].stacktrace.push(line.strip())
  else
    if line =~ /(\d+) prctl\(PR_SET_NAME, "fake vcpu/
      replacements << [$1, "t_vcpu"]
    end
    if line =~ /(\d+) prctl\(PR_SET_NAME, "event_thread/
      replacements << [$1, "t_evnt"]
    end
    events << Event.new(i, line.strip)
  end
end

replacements << [events[0].syscall.split(" ")[0], "t_main"]
i = 0
current_print = nil
started = false
kvm_run = 0
while i < events.length do 
  if events[i].serial_print
    current_print = (current_print || "  print ")+events[i].serial_print
    # current_print = (current_print || "#{events[i].id} print ")+events[i].serial_print
    i+=1
  else
    if current_print and !events[i].is_run?
      if current_print.include? "FAKE"
        started=true
      end
      puts current_print if started
      current_print = nil
    end
    if events[i].is_run?
      kvm_run+=1
    else
      if started
        puts "  > (#{kvm_run})" if kvm_run > 0
        e_str = events[i].inspect
        replacements.each{|(lhs,rhs)| e_str.gsub!(lhs,rhs)}
        e_str.gsub!(/0x[0-9a-f]{3,}/,"0xHEX")
        puts e_str
      end
      kvm_run = 0
    end
    i+=1
  end
end

# 2983 2202037 prctl(PR_SET_NAME, "fake vcpu threa"... <unfinished ...>
#   LSEEK(700416) <- found in both
# LSEEK(14532608) <- only wo snapshot
