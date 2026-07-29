import com.jbytescanner.config.*;
import com.jbytescanner.core.*;
import com.jbytescanner.engine.*;
import java.io.*;
import java.util.*;
public class RuleEngineTaintProbe {
  public static void main(String[] args) throws Exception {
    File ws=new File(args[1]);
    ConfigManager cm=new ConfigManager(); cm.init(ws);
    List<String> pkgs=cm.getConfig().getScanConfig().getScanPackages();
    var loaded=new JarLoader().loadJars(args[0],pkgs);
    var plan=new ClasspathPlanner().plan(loaded,pkgs,ws);
    loaded=plan.jars;
    System.out.printf("planned target=%d dep=%d lib=%d%n",loaded.targetAppJars.size(),loaded.depAppJars.size(),loaded.libJars.size());
    new TaintEngine(loaded.targetAppJars,loaded.depAppJars,loaded.libJars,ws,cm).run();
  }
}