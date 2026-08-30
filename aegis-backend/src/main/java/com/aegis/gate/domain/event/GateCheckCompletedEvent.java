package com.aegis.gate.domain.event;

import com.aegis.gate.domain.GateResult;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.util.UUID;

@Getter
public class GateCheckCompletedEvent extends ApplicationEvent {

    private final UUID gateCheckId;
    private final UUID projectId;
    private final GateResult result;

    public GateCheckCompletedEvent(Object source, UUID gateCheckId, UUID projectId, GateResult result) {
        super(source);
        this.gateCheckId = gateCheckId;
        this.projectId = projectId;
        this.result = result;
    }
}
