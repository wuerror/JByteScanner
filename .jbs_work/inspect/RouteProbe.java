import com.jbytescanner.engine.AsmRouteExtractor;
import java.util.*;
public class RouteProbe {
  public static void main(String[] args) throws Exception {
    String jar=args[0];
    List<List<String>> filters=List.of(
      List.of(),
      List.of("Permission"),
      List.of("io.choerodon.swagger.annotation.Permission"),
      List.of("Lio/choerodon/swagger/annotation/Permission;")
    );
    for (List<String> f: filters) {
      var routes=new AsmRouteExtractor(f,List.of(jar)).extract();
      System.out.println("FILTER="+f+" total="+routes.size());
      routes.stream().filter(r -> r.toString().contains("RuleEngine") || r.toString().contains("rule-engine")).forEach(System.out::println);
    }
  }
}