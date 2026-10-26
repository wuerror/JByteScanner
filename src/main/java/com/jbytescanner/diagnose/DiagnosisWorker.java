package com.jbytescanner.diagnose;

import com.jbytescanner.worker.TaieWorkerRequest;
import com.jbytescanner.worker.TaieWorkerResult;

import java.nio.file.Path;

@FunctionalInterface
public interface DiagnosisWorker {
    TaieWorkerResult run(TaieWorkerRequest request, Path workerDir) throws Exception;
}
