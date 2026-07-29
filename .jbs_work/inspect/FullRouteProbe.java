import com.jbytescanner.core.*;
import com.jbytescanner.engine.*;
import java.io.*;
import java.util.*;
public class FullRouteProbe {
  public static void main(String[] args) throws Exception {
    String target=args[0]; File ws=new File(args[1]); ws.mkdirs();
    List<String> pkgs=List.of("org.hzero","org.srm");
    var loaded=new JarLoader().loadJars(target,pkgs);
    var planned=new ClasspathPlanner().plan(loaded,pkgs,ws).jars;
    System.out.printf("target=%d dep=%d lib=%d%n",planned.targetAppJars.size(),planned.depAppJars.size(),planned.libJars.size());
    for(String p:planned.targetAppJars) if(p.contains("hzero-boot-platform-1.12.0")) System.out.println("PLATFORM="+p);
    var routes=new AsmRouteExtractor(List.of(),planned.targetAppJars).extract();
    System.out.println("routes="+routes.size());
    routes.stream().filter(r -> r.toString().contains("RuleEngine") || r.toString().contains("rule-engine")).forEach(System.out::println);
  }
}