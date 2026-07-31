import com.jbytescanner.core.*;
import com.jbytescanner.engine.*;
import java.io.*;
import java.util.*;
public class FullRouteFilterProbe {
  public static void main(String[] args) throws Exception {
    List<String> pkgs=List.of("org.hzero","org.srm");
    var loaded=new JarLoader().loadJars(args[0],pkgs);
    var planned=new ClasspathPlanner().plan(loaded,pkgs,new File(args[1])).jars;
    List<List<String>> fs=List.of(List.of(),List.of("Permission"),List.of("permissionWithin"),List.of("Anonymous"),List.of("Controller"));
    for(var f:fs){
      var routes=new AsmRouteExtractor(f,planned.targetAppJars).extract();
      long hit=routes.stream().filter(r -> r.toString().contains("RuleEngine") || r.toString().contains("rule-engine")).count();
      System.out.println("FILTER="+f+" routes="+routes.size()+" ruleEngine="+hit);
    }
  }
}