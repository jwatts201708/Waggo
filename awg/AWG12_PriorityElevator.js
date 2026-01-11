
import { EventEmitter } from 'events';

/**
 * @file AWG12_PriorityElevator.js
 * @module AWG12_PriorityElevator
 * @description
 * Elevates jobs with high ROI or governance tags.
 * Re-prioritizes the execution queue based on dynamic metadata.
 */

/**
 * AWG-12: Priority Elevator
 */
export class PriorityElevator extends EventEmitter {
    constructor(config = {}) {
        super();
        this.config = {
            roiThresholdHigh: 0.5, // 0.5 ETH
            roiThresholdUrgent: 2.0,
            ...config
        };
        console.log('[AWG-12] PriorityElevator initialized');
    }

    /**
     * Evaluate and adjust priority of a task
     * @param {Object} task
     * @returns {Object} Enriched task with `priority` field
     */
    elevate(task) {
        let priority = 'standard';
        let score = 0;

        // ROI Check
        const value = task.metadata?.expectedValueEth || 0;
        if (value >= this.config.roiThresholdUrgent) {
            priority = 'urgent';
            score += 100;
        } else if (value >= this.config.roiThresholdHigh) {
            priority = 'high';
            score += 50;
        }

        // Governance Tag Check
        if (task.tags?.includes('governance_critical')) {
            priority = 'urgent';
            score += 200;
        }

        // Deadline Check
        if (task.metadata?.deadline) {
            const timeToDeadline = task.metadata.deadline - Date.now();
            if (timeToDeadline < 5000 && timeToDeadline > 0) {
                // Approaching deadline
                score += 20;
                if (priority === 'standard') priority = 'fast';
            }
        }

        // Apply changes
        if (priority !== (task.priority || 'standard')) {
            task.priority = priority;
            this.emit('elevated', { id: task.id, priority, score });
        }

        task.score = score;
        return task;
    }
}

export default PriorityElevator;
