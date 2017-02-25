package com.kong.bop;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONObject;

public class AuIdId {
  private static int reqNum = 0;

  public static void main(String[] args) {
    // HttpClient httpclient = HttpClients.createDefault();
    // // // 2251253715L, 2180737804L
    // reqNum = 0;
    // long start = System.currentTimeMillis();
    // List<List<Long>> result = Calculate(httpclient, 2273736245L, 2094437628L);
    // long end = System.currentTimeMillis();
    // System.out.println(result.size() + " paths in " + (end - start) / 1000 + " s:");
    // System.out.println(reqNum + " requests to MAG API");
    // System.out.println(result.toString());
  }

  // public static List<List<Long>> Calculate(HttpClient httpclient, Long AuId, Long Id) {
  public static List<List<Long>> Calculate(HttpClient httpclient, Long AuId, Long Id,
      JSONArray entities1) {
    List<List<Long>> result = new ArrayList<List<Long>>();

    String expr = "Id=" + Id + "&count=10000&attributes=F.FId,J.JId,C.CId,AA.AuId";
    JSONObject json = SendRequset(httpclient, expr);
    JSONArray entities = json.optJSONArray("entities");
    if (entities == null || entities.length() == 0) return result;
    JSONObject entity = entities.getJSONObject(0);
    Set<Long> Other = new HashSet<Long>();
    Set<Long> AuIds = new HashSet<>();
    Util.ParseJson(entity, null, Other, AuIds);

    expr = "RId=" + Id + "&count=10000&attributes=Id";
    json = SendRequset(httpclient, expr);
    entities = json.getJSONArray("entities");
    Set<Long> Id3s = new HashSet<Long>();
    for (int i = 0; i < entities.length(); ++i) {
      Id3s.add(entities.getJSONObject(i).getLong("Id"));
    }
    // -- comment when using restful service
    // expr = "Composite(AA.AuId=" + AuId + ")&count=10000&attributes=Id,AA.AuId,AA.AfId";
    // json = SendRequset(httpclient, expr);
    // entities = json.optJSONArray("entities");
    // if (entities == null || entities.length() == 0) return result;
    // -------------------
    // -- comment when testing locally
    entities = entities1;
    // -------------------------------
    Set<Long> Id2s = new HashSet<Long>();
    for (int i = 0; i < entities.length(); ++i) {
      Id2s.add(entities.getJSONObject(i).getLong("Id"));
    }
    Set<Long> AfIds = Util.GetAfIds(entities, AuId);

    // 1-hop
    if (Id2s.contains(Id)) {
      List<Long> element = new ArrayList<>();
      element.add(AuId);
      element.add(Id);
      result.add(element);
    }

    // 2-hop
    List<Long> common = Util.Intersection(Id3s, Id2s);
    for (Long id : common) {
      List<Long> element = new ArrayList<>();
      element.add(AuId);
      element.add(id);
      element.add(Id);
      result.add(element);
    }

    // 3-hop
    // [AuId-id2-other-Id], [AuId-id2-id3-Id]
    int n = Id2s.size();
    int mod = 64;
    if (n > 0) {
      List<Long> ids = new ArrayList<>(Id2s);
      int begin = 0;
      while (true) {
        expr = Util.CreateOR(ids, begin, Math.min(begin + mod - 1, n - 1))
            + "&count=10000&attributes=Id,RId,F.FId,J.JId,C.CId,AA.AuId";
        json = SendRequset(httpclient, expr);
        entities = json.optJSONArray("entities");
        if (entities != null) {
          for (int i = 0; i < entities.length(); i++) {
            JSONObject obj = entities.getJSONObject(i);
            Long id = obj.getLong("Id");
            Set<Long> RId = new HashSet<>();
            Set<Long> Other2 = new HashSet<>();
            Util.ParseJson(obj, RId, Other2, null);
            List<Long> same = Util.Intersection(Other2, Other);
            for (Long other : same) {
              List<Long> element = new ArrayList<>();
              element.add(AuId);
              element.add(id);
              element.add(other);
              element.add(Id);
              result.add(element);
            }
            same = Util.Intersection(RId, Id3s);
            for (Long rid : same) {
              List<Long> element = new ArrayList<>();
              element.add(AuId);
              element.add(id);
              element.add(rid);
              element.add(Id);
              result.add(element);
            }
          }
        }

        begin += mod;
        if (begin > n - 1) break;
      }
    }

    // [AuId-AfId-AuId-Id]
    if (AuIds.contains(AuId)) {
      for (Long afid : AfIds) {
        List<Long> element = new ArrayList<>();
        element.add(AuId);
        element.add(afid);
        element.add(AuId);
        element.add(Id);
        result.add(element);
      }
      AuIds.remove(AuId);
    }

    // [AuId-AfId-AuId2-Id]
    for (Long auid : AuIds) {
      expr = "Composite(AA.AuId=" + auid + ")&count=10000&attributes=AA.AuId,AA.AfId";
      json = SendRequset(httpclient, expr);
      entities = json.optJSONArray("entities");
      if (entities != null) {
        Set<Long> afids = Util.GetAfIds(entities, auid);
        List<Long> same = Util.Intersection(afids, AfIds);
        for (Long afid : same) {
          List<Long> element = new ArrayList<>();
          element.add(AuId);
          element.add(afid);
          element.add(auid);
          element.add(Id);
          result.add(element);
        }
      }
    }

    return result;
  }

  public static JSONObject SendRequset(HttpClient httpclient, String expr) {
    ++reqNum;
    String response = MAGAPI.Get(httpclient, expr);
    // System.out.println(response);
    // error checking
    // while (response == null) response = MAGAPI.Get(httpclient, expr);
    // while(regex解析response的值为error) response = MAGAPI.Get(httpclient, expr);
    return new JSONObject(response);
  }
}
