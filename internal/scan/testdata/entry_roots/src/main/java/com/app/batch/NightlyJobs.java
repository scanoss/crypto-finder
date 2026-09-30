package com.app.batch;

import com.app.service.StatementExport;

public final class NightlyJobs {
    public static void main(String[] args) throws Exception {
        archiveStatement(new StatementExport());
    }

    private static void archiveStatement(StatementExport export) throws Exception {
        export.encryptForArchive(new byte[0]);
    }
}
